import NIOCore
import Logging

public struct MySQLPacketDecoder: ByteToMessageDecoder {
    public typealias InboundOut = MySQLPacket

    public let sequence: MySQLPacketSequence
    let logger: Logger
    /// The payload so far of a packet sent in several parts (each 0xFFFFFF bytes but the last).
    private var partial: ByteBuffer?
    /// The longest payload accepted, continuations included.
    let maxMessageLength: Int

    /// 1 GiB, the most `max_allowed_packet` allows: a server never sends more, so a longer
    /// message (endless continuations) is a broken or hostile peer, not data to buffer.
    static let maxMessageLength = 1 << 30
    
    public init(sequence: MySQLPacketSequence, logger: Logger) {
        self.init(sequence: sequence, logger: logger, maxMessageLength: Self.maxMessageLength)
    }

    init(sequence: MySQLPacketSequence, logger: Logger, maxMessageLength: Int) {
        self.sequence = sequence
        self.logger = logger
        self.maxMessageLength = maxMessageLength
    }
    
    public mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        var copy = buffer
        guard let header = copy.readInteger(endianness: .little, as: UInt32.self) else {
            return .needMoreData
        }
        // header = 01     00 00 01
        //          <seq>  <length>
        let length = header & 0x00_FF_FF_FF
        let sequenceID = header >> 24
        // print("header: \(header) length: \(length) seq: \(sequenceID)")
        // Checked on the header, before waiting for (and buffering) the payload.
        guard (self.partial?.readableBytes ?? 0) + Int(length) <= self.maxMessageLength else {
            self.partial = nil
            throw MySQLError.packetTooLarge(limit: self.maxMessageLength)
        }
        guard var payload = copy.readSlice(length: numericCast(length)) else {
            return .needMoreData
        }
        buffer = copy
        self.sequence.current = UInt8(sequenceID & 0xFF)
        // A full-size packet continues in the next one; the first shorter packet ends it.
        if length == MySQLPacketEncoder.maxPayloadLength {
            self.partial.setOrWriteBuffer(&payload)
            return .continue
        }
        if var partial = self.partial {
            partial.writeBuffer(&payload)
            payload = partial
            self.partial = nil
        }
        let packet = MySQLPacket(payload: payload)
        self.logger.trace("MySQLPacketDecoder.decode: \(packet)")
        context.fireChannelRead(self.wrapInboundOut(packet))
        return .continue
    }
    
    public mutating func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        .needMoreData
    }
}
