import Logging
import NIOCore

public final class MySQLPacketEncoder: MessageToByteEncoder {
    public typealias OutboundIn = MySQLPacket
    
    /// The largest payload of one packet; a longer payload continues in the next packets.
    static let maxPayloadLength = 0xFF_FFFF

    public let sequence: MySQLPacketSequence
    let logger: Logger

    public init(sequence: MySQLPacketSequence, logger: Logger) {
        self.sequence = sequence
        self.logger = logger
    }
    
    public func encode(data: MySQLPacket, out: inout ByteBuffer) throws {
        var packet = data
        self.logger.trace("MySQLPacketDecoder.encode: \(packet)")
        // A payload of 0xFFFFFF bytes or more goes out in 0xFFFFFF-byte packets with consecutive
        // sequence ids, ended by a shorter packet (empty for an exact multiple).
        while packet.payload.readableBytes >= Self.maxPayloadLength {
            var chunk = packet.payload.readSlice(length: Self.maxPayloadLength)!
            self.writePacket(&chunk, out: &out)
        }
        self.writePacket(&packet.payload, out: &out)
    }

    private func writePacket(_ payload: inout ByteBuffer, out: inout ByteBuffer) {
        let length = payload.readableBytes
        out.writeInteger(UInt8(length & 0xFF))
        out.writeInteger(UInt8(length >> 8 & 0xFF))
        out.writeInteger(UInt8(length >> 16 & 0xFF))
        out.writeInteger(UInt8(self.sequence.next()))
        out.writeBuffer(&payload)
    }
}
