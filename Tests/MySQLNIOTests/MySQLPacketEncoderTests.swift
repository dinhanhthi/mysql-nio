import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import Testing

/// Patch D: payloads of 0xFFFFFF bytes or more travel as several packets (MySQL protocol
/// "sending more than 16 MiB"): 0xFFFFFF-byte chunks with consecutive sequence ids, ended by
/// a shorter packet (empty when the payload is an exact multiple).
@Suite
struct MySQLPacketEncoderTests {
    static let max = 0xFF_FFFF

    @Test(arguments: [0, 1, 1000, max - 1])
    func payloadBelowTheMaximumIsOnePacket(size: Int) throws {
        let frames = try Self.encode(size: size)
        #expect(frames.map(\.length) == [size])
        #expect(frames.map(\.sequenceID) == [0])
        #expect(frames.flatMap(\.payload) == Self.payload(size: size))
    }

    @Test
    func exactlyTheMaximumIsFollowedByAnEmptyPacket() throws {
        let frames = try Self.encode(size: Self.max)
        #expect(frames.map(\.length) == [Self.max, 0])
        #expect(frames.map(\.sequenceID) == [0, 1])
        #expect(frames.flatMap(\.payload) == Self.payload(size: Self.max))
    }

    @Test
    func aboveTheMaximumIsSplit() throws {
        let frames = try Self.encode(size: Self.max + 10)
        #expect(frames.map(\.length) == [Self.max, 10])
        #expect(frames.map(\.sequenceID) == [0, 1])
        #expect(frames.flatMap(\.payload) == Self.payload(size: Self.max + 10))
    }

    @Test
    func twiceTheMaximumIsTwoFullPacketsAndAnEmptyOne() throws {
        let frames = try Self.encode(size: 2 * Self.max)
        #expect(frames.map(\.length) == [Self.max, Self.max, 0])
        #expect(frames.map(\.sequenceID) == [0, 1, 2])
        #expect(frames.flatMap(\.payload) == Self.payload(size: 2 * Self.max))
    }

    @Test
    func theNextPacketContinuesTheSequenceAfterASplit() throws {
        let sequence = MySQLPacketSequence()
        let encoder = MySQLPacketEncoder(sequence: sequence, logger: .init(label: "test"))
        var out = ByteBuffer()
        try encoder.encode(data: MySQLPacket(payload: ByteBuffer(bytes: Self.payload(size: Self.max))), out: &out)
        try encoder.encode(data: MySQLPacket(payload: ByteBuffer(bytes: [1, 2, 3])), out: &out)
        #expect(Self.frames(out).map(\.sequenceID) == [0, 1, 2])
    }

    // MARK: - Helpers

    struct Frame {
        var length: Int
        var sequenceID: UInt8
        var payload: [UInt8]
    }

    /// A payload whose bytes depend on their offset, so a misplaced chunk shows.
    static func payload(size: Int) -> [UInt8] {
        (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 8) }
    }

    static func encode(size: Int) throws -> [Frame] {
        let encoder = MySQLPacketEncoder(sequence: MySQLPacketSequence(), logger: .init(label: "test"))
        var out = ByteBuffer()
        try encoder.encode(data: MySQLPacket(payload: ByteBuffer(bytes: Self.payload(size: size))), out: &out)
        return Self.frames(out)
    }

    /// Splits `buffer` into its packets: 3-byte little-endian length, sequence id, payload.
    static func frames(_ buffer: ByteBuffer) -> [Frame] {
        var buffer = buffer
        var frames: [Frame] = []
        while let header = buffer.readBytes(length: 4) {
            let length = Int(header[0]) | Int(header[1]) << 8 | Int(header[2]) << 16
            guard let payload = buffer.readBytes(length: length) else {
                Issue.record("truncated packet")
                break
            }
            frames.append(Frame(length: length, sequenceID: header[3], payload: payload))
        }
        #expect(buffer.readableBytes == 0)
        return frames
    }
}

/// Patch D: the decoder joins a 0xFFFFFF-byte packet with the packets that follow it, up to
/// the first shorter one, into one `MySQLPacket`; the sequence follows the last packet. A
/// message longer than the cap fails as soon as a header announces it.
@Suite
struct MySQLPacketDecoderTests {
    static let max = MySQLPacketEncoderTests.max

    @Test(arguments: [0, 1000, max - 1])
    func payloadBelowTheMaximumIsOnePacket(size: Int) throws {
        try Self.expectReassembled(size: size, lengths: [size])
    }

    @Test
    func exactlyTheMaximumAndAnEmptyPacketIsOnePayload() throws {
        try Self.expectReassembled(size: Self.max, lengths: [Self.max, 0])
    }

    @Test
    func aboveTheMaximumIsOnePayload() throws {
        try Self.expectReassembled(size: Self.max + 10, lengths: [Self.max, 10])
    }

    @Test
    func twiceTheMaximumIsOnePayload() throws {
        try Self.expectReassembled(size: 2 * Self.max, lengths: [Self.max, Self.max, 0])
    }

    @Test
    func continuationArrivingLaterIsJoined() throws {
        let sequence = MySQLPacketSequence()
        let channel = try Self.channel(sequence)
        let payload = MySQLPacketEncoderTests.payload(size: Self.max + 10)
        let wire = Self.wire(payload, lengths: [Self.max, 10], firstID: 1)
        let split = Self.max + 4 + 2 // the first packet and part of the second header
        try channel.writeInbound(ByteBuffer(bytes: wire[..<split]))
        #expect(try channel.readInbound(as: MySQLPacket.self) == nil)
        try channel.writeInbound(ByteBuffer(bytes: wire[split...]))
        let packet = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(Array(buffer: packet.payload) == payload)
        #expect(sequence.current == 2)
        _ = try channel.finish()
    }

    @Test
    func packetsAfterASplitAreSeparate() throws {
        let sequence = MySQLPacketSequence()
        let channel = try Self.channel(sequence)
        let payload = MySQLPacketEncoderTests.payload(size: Self.max)
        var wire = Self.wire(payload, lengths: [Self.max, 0], firstID: 1)
        wire += Self.wire([7, 8], lengths: [2], firstID: 3)
        try channel.writeInbound(ByteBuffer(bytes: wire))
        #expect(Array(buffer: try #require(try channel.readInbound(as: MySQLPacket.self)).payload) == payload)
        #expect(Array(buffer: try #require(try channel.readInbound(as: MySQLPacket.self)).payload) == [7, 8])
        #expect(sequence.current == 3)
        _ = try channel.finish()
    }

    // MARK: - Size cap

    @Test
    func theDefaultCapIsOneGiB() {
        #expect(MySQLPacketDecoder.maxMessageLength == 1 << 30)
    }

    @Test
    func aHeaderOverTheCapFailsBeforeItsPayloadArrives() throws {
        let channel = try Self.channel(MySQLPacketSequence(), maxMessageLength: 100)
        // Only the header of a full-size packet: nothing of the payload is buffered.
        #expect(throws: MySQLError.packetTooLarge(limit: 100)) {
            try channel.writeInbound(ByteBuffer(bytes: [0xFF, 0xFF, 0xFF, 1]))
        }
        _ = try? channel.finish()
    }

    @Test
    func continuationsOverTheCapFail() throws {
        let cap = Self.max + 5
        let channel = try Self.channel(MySQLPacketSequence(), maxMessageLength: cap)
        let payload = MySQLPacketEncoderTests.payload(size: Self.max + 6)
        let wire = Self.wire(payload, lengths: [Self.max, 6], firstID: 1)
        try channel.writeInbound(ByteBuffer(bytes: wire[..<(Self.max + 4)]))
        // The next header would take the message past the cap.
        #expect(throws: MySQLError.packetTooLarge(limit: cap)) {
            try channel.writeInbound(ByteBuffer(bytes: wire[(Self.max + 4)..<(Self.max + 8)]))
        }
        _ = try? channel.finish()
    }

    @Test
    func aMessageOfExactlyTheCapIsAccepted() throws {
        let cap = Self.max + 5
        let channel = try Self.channel(MySQLPacketSequence(), maxMessageLength: cap)
        let payload = MySQLPacketEncoderTests.payload(size: cap)
        try channel.writeInbound(ByteBuffer(bytes: Self.wire(payload, lengths: [Self.max, 5], firstID: 1)))
        #expect(Array(buffer: try #require(try channel.readInbound(as: MySQLPacket.self)).payload) == payload)
        _ = try channel.finish()
    }

    // MARK: - Helpers

    static func expectReassembled(size: Int, lengths: [Int]) throws {
        let sequence = MySQLPacketSequence()
        let channel = try Self.channel(sequence)
        let payload = MySQLPacketEncoderTests.payload(size: size)
        try channel.writeInbound(ByteBuffer(bytes: Self.wire(payload, lengths: lengths, firstID: 1)))
        let packet = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(Array(buffer: packet.payload) == payload)
        #expect(try channel.readInbound(as: MySQLPacket.self) == nil)
        #expect(sequence.current == UInt8(lengths.count))
        _ = try channel.finish()
    }

    static func channel(
        _ sequence: MySQLPacketSequence, maxMessageLength: Int = MySQLPacketDecoder.maxMessageLength
    ) throws -> EmbeddedChannel {
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(
            ByteToMessageHandler(MySQLPacketDecoder(
                sequence: sequence, logger: .init(label: "test"), maxMessageLength: maxMessageLength
            ))
        )
        return channel
    }

    /// `payload` cut into packets of `lengths`, with sequence ids from `firstID`.
    static func wire(_ payload: [UInt8], lengths: [Int], firstID: UInt8) -> [UInt8] {
        var wire: [UInt8] = []
        var offset = 0
        for (index, length) in lengths.enumerated() {
            wire += [UInt8(length & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length >> 16 & 0xFF), firstID &+ UInt8(index)]
            wire += payload[offset..<(offset + length)]
            offset += length
        }
        return wire
    }
}
