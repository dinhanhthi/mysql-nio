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

    // MARK: - Patch B: caching_sha2_password uses the 20-byte nonce (integration)

    @Test(.enabled(if: env("DBLORE_PATCH_INTEGRATION") != nil))
    func cachingSha2LongPasswordOverPlainTCPThenFastAuth() async throws {
        let user = "dblore_patch_sha2"
        let password = "Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8*" // 32 chars
        #expect(password.count == 32)
        let port = env("DBLORE_MYSQL_PORT").flatMap(Int.init) ?? 3307
        let database = env("DBLORE_DATABASE") ?? "dblore_test"

        let root = try await Self.connect(port: port, user: "root", password: env("DBLORE_ROOT_PASSWORD") ?? "dblore123", database: database, tls: Self.insecureTLS())
        do {
            _ = try await root.simpleQuery("DROP USER IF EXISTS '\(user)'@'%'").get()
            _ = try await root.simpleQuery("CREATE USER '\(user)'@'%' IDENTIFIED WITH caching_sha2_password BY '\(password)'").get()
            _ = try await root.simpleQuery("GRANT SELECT ON `\(database)`.* TO '\(user)'@'%'").get()
        } catch {
            try? await root.close().get()
            throw error
        }

        do {
            // First connect: fresh user, server cache is cold -> full auth via RSA over plain TCP.
            let first = LogCapture()
            let c1 = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, logger: first.logger)
            let r1 = try await c1.simpleQuery("SELECT 1 AS one").get()
            try await c1.close().get()
            #expect(r1.first?.column("one")?.int == 1)
            #expect(first.contains("perform_full_authentication"))

            // Second connect: cache is warm -> fast auth must succeed (requires the correct 20-byte scramble).
            let second = LogCapture()
            let c2 = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, logger: second.logger)
            try await c2.close().get()
            #expect(second.contains("fast_auth_success"))
            #expect(!second.contains("perform_full_authentication"))
        } catch {
            _ = try? await root.simpleQuery("DROP USER IF EXISTS '\(user)'@'%'").get()
            try? await root.close().get()
            throw error
        }
        _ = try await root.simpleQuery("DROP USER IF EXISTS '\(user)'@'%'").get()
        try await root.close().get()
    }

    @Test(.enabled(if: env("DBLORE_PATCH_INTEGRATION") != nil))
    func mariaDBNativePasswordStillWorks() async throws {
        let conn = try await Self.connect(
            port: env("DBLORE_MARIADB_PORT").flatMap(Int.init) ?? 3308,
            user: env("DBLORE_USER") ?? "dblore_test",
            password: env("DBLORE_PASSWORD") ?? "dblore123",
            database: env("DBLORE_DATABASE") ?? "dblore_test",
            tls: nil
        )
        let rows = try await conn.simpleQuery("SELECT 1 AS one").get()
        try await conn.close().get()
        #expect(rows.first?.column("one")?.int == 1)
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

    static func insecureTLS() -> TLSConfiguration {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.certificateVerification = .none
        return tls
    }

    static func connect(
        port: Int, user: String, password: String, database: String,
        tls: TLSConfiguration?, logger: Logger = .init(label: "dblore.patch")
    ) async throws -> MySQLConnection {
        let addr = try SocketAddress.makeAddressResolvingHost(env("DBLORE_HOST") ?? "127.0.0.1", port: port)
        return try await MySQLConnection.connect(
            to: addr, username: user, database: database, password: password,
            tlsConfiguration: tls, logger: logger,
            on: MultiThreadedEventLoopGroup.singletonMultiThreadedEventLoopGroup.any()
        ).get()
    }
}

/// Holds a future's result; only touched on the EmbeddedEventLoop's (single) thread.
final class OutcomeBox: @unchecked Sendable {
    var value: Result<Void, any Error>?
}

/// Captures log messages at `.trace` so tests can observe which auth path was taken.
final class LogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    var logger: Logger {
        var logger = Logger(label: "dblore.patch.capture") { _ in Handler(capture: self) }
        logger.logLevel = .trace
        return logger
    }

    func contains(_ needle: String) -> Bool {
        self.lock.withLock { self.messages.contains { $0.contains(needle) } }
    }

    fileprivate func append(_ message: String) {
        self.lock.withLock { self.messages.append(message) }
    }

    struct Handler: LogHandler {
        let capture: LogCapture
        var metadata: Logger.Metadata = [:]
        var logLevel: Logger.Level = .trace

        subscript(metadataKey key: String) -> Logger.Metadata.Value? {
            get { self.metadata[key] }
            set { self.metadata[key] = newValue }
        }

        func log(event: LogEvent) {
            self.capture.append(event.message.description)
        }
    }
}
