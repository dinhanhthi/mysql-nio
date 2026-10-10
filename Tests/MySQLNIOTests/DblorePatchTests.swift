import Foundation
import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOSSL
import Testing

/// Tests for the dblore fork patches (TLS downgrade refusal, caching_sha2 20-byte scramble,
/// no plain-text public key retrieval by default, failing the login when the channel closes).
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
            let c1 = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, allowPublicKeyRetrieval: true, logger: first.logger)
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

    // MARK: - Patch C: no RSA public key retrieval over plain TCP unless allowed

    @Test
    func fullAuthWithoutTLSIsRefusedByDefault() throws {
        let (channel, done) = try Self.authenticating(isTLS: false, allowPublicKeyRetrieval: false)

        try channel.writeInbound(MySQLPacket(payload: Self.performFullAuthentication()))

        #expect(try channel.readOutbound(as: MySQLPacket.self) == nil) // no request_public_key, no COM_QUIT
        #expect(!channel.isActive)
        #expect(Self.failure(of: done) as? MySQLError == .publicKeyRetrievalNotAllowed)
        _ = try? channel.finish()
    }

    @Test
    func fullAuthWithoutTLSRequestsThePublicKeyWhenAllowed() throws {
        let (channel, done) = try Self.authenticating(isTLS: false, allowPublicKeyRetrieval: true)

        try channel.writeInbound(MySQLPacket(payload: Self.performFullAuthentication()))

        let packet = try #require(try channel.readOutbound(as: MySQLPacket.self))
        #expect(Array(buffer: packet.payload) == [0x02])
        done.succeed(())
        _ = try? channel.finish()
    }

    @Test
    func fullAuthOverTLSStillSendsThePassword() throws {
        let (channel, done) = try Self.authenticating(isTLS: true, allowPublicKeyRetrieval: false)

        try channel.writeInbound(MySQLPacket(payload: Self.performFullAuthentication()))

        let packet = try #require(try channel.readOutbound(as: MySQLPacket.self))
        #expect(Array(buffer: packet.payload) == Array("p".utf8) + [0])
        done.succeed(())
        _ = try? channel.finish()
    }

    // MARK: - Patch C: a channel that closes during the login fails the connect promise

    @Test
    func channelClosedDuringHandshakeFailsTheLogin() throws {
        let channel = EmbeddedChannel()
        let done = channel.eventLoop.makePromise(of: Void.self)
        try channel.pipeline.syncOperations.addHandler(Self.handler(tls: nil, done: done))
        channel.pipeline.fireChannelActive()

        _ = try? channel.close().wait()

        #expect(Self.failure(of: done) as? MySQLError == .closed)
    }

    @Test
    func channelClosedDuringAuthenticationFailsTheLogin() throws {
        let (channel, done) = try Self.authenticating(isTLS: false, allowPublicKeyRetrieval: true)

        _ = try? channel.close().wait()

        #expect(Self.failure(of: done) as? MySQLError == .closed)
    }

    @Test(.enabled(if: env("DBLORE_PATCH_INTEGRATION") != nil))
    func cachingSha2PublicKeyRetrievalOverPlainTCP() async throws {
        let user = "dblore_patch_rsa"
        let password = "dblore-patch-rsa-pw"
        let port = env("DBLORE_MYSQL_PORT").flatMap(Int.init) ?? 3307
        let database = env("DBLORE_DATABASE") ?? "dblore_test"

        let root = try await Self.connect(port: port, user: "root", password: env("DBLORE_ROOT_PASSWORD") ?? "dblore123", database: database, tls: Self.insecureTLS())
        func cleanUp() async {
            _ = try? await root.simpleQuery("DROP USER IF EXISTS '\(user)'@'%'").get()
            try? await root.close().get()
        }
        do {
            _ = try await root.simpleQuery("DROP USER IF EXISTS '\(user)'@'%'").get()
            _ = try await root.simpleQuery("CREATE USER '\(user)'@'%' IDENTIFIED WITH caching_sha2_password BY '\(password)'").get()
            _ = try await root.simpleQuery("GRANT SELECT ON `\(database)`.* TO '\(user)'@'%'").get()

            // Cold cache, plain TCP, default: refused before any key request.
            let refused = LogCapture()
            do {
                let c = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, logger: refused.logger)
                try? await c.close().get()
                Issue.record("plain-TCP full authentication succeeded without allowPublicKeyRetrieval")
            } catch {
                #expect(error as? MySQLError == .publicKeyRetrievalNotAllowed, "\(error)")
            }
            #expect(refused.contains("perform_full_authentication"))
            #expect(!refused.contains("sending request_public_key"))

            // Opted in: RSA full authentication works.
            let allowed = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, allowPublicKeyRetrieval: true)
            try await allowed.close().get()

            // Cache cleared, then filled by a TLS login: plain TCP fast auth needs no flag.
            _ = try await root.simpleQuery("FLUSH PRIVILEGES").get()
            let tls = try await Self.connect(port: port, user: user, password: password, database: database, tls: Self.insecureTLS())
            try await tls.close().get()
            let fast = LogCapture()
            let plain = try await Self.connect(port: port, user: user, password: password, database: database, tls: nil, logger: fast.logger)
            let rows = try await plain.simpleQuery("SELECT 1 AS one").get()
            try await plain.close().get()
            #expect(rows.first?.column("one")?.int == 1)
            #expect(fast.contains("fast_auth_success"))
        } catch {
            await cleanUp()
            throw error
        }
        await cleanUp()
    }

    // MARK: - Helpers

    /// A handler past the HandshakeResponse41, waiting for the caching_sha2_password reply.
    static func authenticating(
        isTLS: Bool, allowPublicKeyRetrieval: Bool
    ) throws -> (EmbeddedChannel, EventLoopPromise<Void>) {
        let channel = EmbeddedChannel()
        let done = channel.eventLoop.makePromise(of: Void.self)
        let handler = MySQLConnectionHandler(
            logger: .init(label: "test"),
            state: .authenticating(.init(
                authPluginName: "caching_sha2_password", password: "p", isTLS: isTLS,
                savedSeedValue: Array(repeating: 0x41, count: 20),
                awaitingCachingSha2PluginPublicKey: false,
                allowPublicKeyRetrieval: allowPublicKeyRetrieval, done: done
            )),
            sequence: MySQLPacketSequence()
        )
        handler.serverCapabilities = [.CLIENT_PROTOCOL_41, .CLIENT_SECURE_CONNECTION, .CLIENT_PLUGIN_AUTH]
        try channel.pipeline.syncOperations.addHandler(handler)
        channel.pipeline.fireChannelActive()
        return (channel, done)
    }

    /// AuthMoreData `perform_full_authentication` (0x01 0x04).
    static func performFullAuthentication() -> ByteBuffer {
        ByteBuffer(bytes: [0x01, 0x04])
    }

    /// The error of an already-failed promise; records an issue if it is pending or succeeded.
    /// (EmbeddedEventLoop: never `wait()` on a pending promise, it would hang.)
    static func failure(of promise: EventLoopPromise<Void>) -> (any Error)? {
        let outcome = OutcomeBox()
        promise.futureResult.whenComplete { outcome.value = $0 }
        switch outcome.value {
        case .failure(let error): return error
        case .success: Issue.record("login unexpectedly succeeded")
        case nil: Issue.record("login promise still pending")
        }
        return nil
    }

    static func handler(tls: TLSConfiguration?, done: EventLoopPromise<Void>) -> MySQLConnectionHandler {
        MySQLConnectionHandler(
            logger: .init(label: "test"),
            state: .handshake(.init(
                username: "u", database: "d", password: "p",
                tlsConfiguration: tls, serverHostname: nil, allowPublicKeyRetrieval: false, done: done
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
        tls: TLSConfiguration?, allowPublicKeyRetrieval: Bool = false,
        logger: Logger = .init(label: "dblore.patch")
    ) async throws -> MySQLConnection {
        let addr = try SocketAddress.makeAddressResolvingHost(env("DBLORE_HOST") ?? "127.0.0.1", port: port)
        return try await MySQLConnection.connect(
            to: addr, username: user, database: database, password: password,
            tlsConfiguration: tls, allowPublicKeyRetrieval: allowPublicKeyRetrieval, logger: logger,
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
