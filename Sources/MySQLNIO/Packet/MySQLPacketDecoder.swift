import NIOCore
import Logging

public struct MySQLPacketDecoder: ByteToMessageDecoder {
    public typealias InboundOut = MySQLPacket

    public let sequence: MySQLPacketSequence
    let logger: Logger
    /// The payload so far of a packet sent in several parts (each 0xFFFFFF bytes but the last).
    private var partial: ByteBuffer?
    
    public init(sequence: MySQLPacketSequence, logger: Logger) {
        self.sequence = sequence
        self.logger = logger
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
