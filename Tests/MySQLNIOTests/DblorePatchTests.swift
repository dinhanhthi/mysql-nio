import Foundation
import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOSSL
import Testing

/// Tests for the dblore fork patches (TLS downgrade refusal, caching_sha2 20-byte scramble).
@Suite(.serialized)
struct DblorePatchTests {
    init() {
        #expect(isLoggingConfigured)
    }

    // MARK: - Patch A: refuse to continue in plaintext when TLS was requested

    @Test
    func tlsRequestedButServerLacksClientSSLFailsWithoutSendingAuth() throws {
        let channel = EmbeddedChannel()
        let done = channel.eventLoop.makePromise(of: Void.self)
        try channel.pipeline.syncOperations.addHandler(Self.handler(tls: .makeClientConfiguration(), done: done))

        try channel.writeInbound(MySQLPacket(payload: Self.handshakeV10WithoutSSL()))

        #expect(try channel.readOutbound(as: MySQLPacket.self) == nil)
        // EmbeddedEventLoop: never `wait()` here (it would hang if the promise is pending).
        let outcome = OutcomeBox()
        done.futureResult.whenComplete { outcome.value = $0 }
        guard case .failure(let error) = try #require(outcome.value) else {
            Issue.record("handshake unexpectedly succeeded")
            return
        }
        #expect(error as? MySQLError == .tlsNotSupportedByServer)
        _ = try? channel.finish()
    }

    @Test
    func noTLSRequestedStillSendsHandshakeResponse() throws {
        let channel = EmbeddedChannel()
        let done = channel.eventLoop.makePromise(of: Void.self)
        try channel.pipeline.syncOperations.addHandler(Self.handler(tls: nil, done: done))

        try channel.writeInbound(MySQLPacket(payload: Self.handshakeV10WithoutSSL()))

        #expect(try channel.readOutbound(as: MySQLPacket.self) != nil)
        done.succeed(()) // avoid leaking an unfulfilled promise
        _ = try? channel.finish()
    }

    // MARK: - Helpers

    static func handler(tls: TLSConfiguration?, done: EventLoopPromise<Void>) -> MySQLConnectionHandler {
        MySQLConnectionHandler(
            logger: .init(label: "test"),
            state: .handshake(.init(
                username: "u", database: "d", password: "p",
                tlsConfiguration: tls, serverHostname: nil, done: done
            )),
            sequence: MySQLPacketSequence()
        )
    }

    /// A MySQL 8-style HandshakeV10 payload that does NOT advertise `CLIENT_SSL`.
    static func handshakeV10WithoutSSL() -> ByteBuffer {
        let caps: MySQLProtocol.CapabilityFlags = [
            .CLIENT_LONG_PASSWORD, .CLIENT_PROTOCOL_41, .CLIENT_SECURE_CONNECTION,
            .CLIENT_PLUGIN_AUTH, .CLIENT_CONNECT_WITH_DB, .CLIENT_TRANSACTIONS,
        ]
        let raw = UInt32(truncatingIfNeeded: caps.rawValue)
        var buf = ByteBufferAllocator().buffer(capacity: 128)
        buf.writeInteger(UInt8(10))
        buf.writeString("8.4.0"); buf.writeInteger(UInt8(0))
        buf.writeInteger(UInt32(1), endianness: .little)
        buf.writeBytes(Array(repeating: UInt8(0x41), count: 8)) // auth-plugin-data part 1
        buf.writeInteger(UInt8(0)) // filler
        buf.writeInteger(UInt16(truncatingIfNeeded: raw), endianness: .little)
        buf.writeInteger(UInt8(0xff)) // utf8mb4_0900_ai_ci
        buf.writeInteger(UInt16(2), endianness: .little) // SERVER_STATUS_AUTOCOMMIT
        buf.writeInteger(UInt16(truncatingIfNeeded: raw >> 16), endianness: .little)
        buf.writeInteger(UInt8(21)) // auth-plugin-data length
        buf.writeBytes(Array(repeating: UInt8(0), count: 10)) // reserved
        buf.writeBytes(Array(repeating: UInt8(0x42), count: 12) + [0]) // auth-plugin-data part 2 + NUL
        buf.writeString("caching_sha2_password"); buf.writeInteger(UInt8(0))
        return buf
    }
}

/// Holds a future's result; only touched on the EmbeddedEventLoop's (single) thread.
final class OutcomeBox: @unchecked Sendable {
    var value: Result<Void, any Error>?
}
