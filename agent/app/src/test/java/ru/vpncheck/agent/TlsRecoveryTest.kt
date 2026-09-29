package ru.vpncheck.agent

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.security.SecureRandom

class TlsRecoveryTest {
    private val oldCert = HeldCertificate.Builder().commonName(HOST).ecdsa256().build()
    private val newCert = HeldCertificate.Builder().commonName(HOST).ecdsa256().build()
    private val tlsServer = MockWebServer()
    private val plainServer = MockWebServer()
    private val signing = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
    private val otherSigning = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
    private var previousKey = ""
    private lateinit var server: String

    @Before
    fun start() {
        tlsServer.useHttps(HandshakeCertificates.Builder().heldCertificate(newCert).build().sslSocketFactory(), false)
        tlsServer.start(InetAddress.getByName(HOST), 0)
        plainServer.start(InetAddress.getByName(HOST), 0)
        server = "http://$HOST:${plainServer.port}"
        Api.base = server
        previousKey = Verify.manifestKey
        Verify.manifestKey = hex((signing.public as Ed25519PublicKeyParameters).encoded)
    }

    @After
    fun stop() {
        Api.useTls(null)
        Verify.manifestKey = previousKey
        tlsServer.shutdown()
        plainServer.shutdown()
    }

    @Test
    fun newKeyOnServerIsRecoveredFromSignedManifestOverHttp() {
        val stored = PinnedTls(HOST, tlsServer.port, PinnedTls.pinOf(oldCert.certificate))
        Api.useTls(stored)
        try {
            Api.ping("agent")
            fail("old pin must fail")
        } catch (e: IOException) {
            assertTrue(PinnedTls.needsRecovery(e))
        }
        val fresh = manifest(200, tls(PinnedTls.pinOf(newCert.certificate)))
        plainServer.enqueue(MockResponse().setBody(JSONObject().put("manifest", fresh).toString()))
        val change = PinnedTls.fromManifest(server, 100, 150, Api.manifestOverHttp())
        assertEquals("/v1/manifest", plainServer.takeRequest().path)
        assertNotNull(change?.tls)
        assertEquals(200L, change?.issued)
        Api.useTls(change?.tls)
        tlsServer.enqueue(MockResponse().setBody("""{"ok":true}"""))
        assertTrue(Api.ping("agent").getBoolean("ok"))
        assertEquals(1, plainServer.requestCount)
    }

    @Test
    fun olderOrEqualManifestDoesNotChangeTls() {
        val oldPin = tls(PinnedTls.pinOf(oldCert.certificate))
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(200, oldPin)))
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(150, oldPin)))
        assertNull(PinnedTls.fromManifest(server, 100, 300, manifest(200, oldPin)))
    }

    @Test
    fun oldManifestWithoutTlsKeyNeverTurnsTlsOff() {
        val bare = manifest(300, null)
        assertNull(PinnedTls.fromManifest(server, 0, 0, bare))
        assertNull(PinnedTls.fromManifest(server, 200, 0, bare))
        val stored = PinnedTls(HOST, tlsServer.port, PinnedTls.pinOf(oldCert.certificate))
        Api.useTls(stored)
        try {
            Api.ping("agent")
            fail("old pin must fail")
        } catch (e: IOException) {
            assertTrue(PinnedTls.needsRecovery(e))
        }
        plainServer.enqueue(MockResponse().setBody(JSONObject().put("manifest", bare).toString()))
        assertNull(PinnedTls.fromManifest(server, 0, 0, Api.manifestOverHttp()))
    }

    @Test
    fun explicitNullOrOffTurnsTlsOffOnlyWhenSignedAndNewer() {
        val explicitNull = manifest(300, JSONObject.NULL)
        val off = PinnedTls.fromManifest(server, 200, 0, explicitNull)
        assertNotNull(off)
        assertNull(off?.tls)
        assertEquals(300L, off?.issued)
        assertNull(PinnedTls.fromManifest(server, 300, 0, explicitNull))
        assertNull(PinnedTls.fromManifest(server, 400, 0, explicitNull))
        assertNull(PinnedTls.fromManifest(server, 200, 350, explicitNull))
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(300, JSONObject.NULL).apply { put("issued", 900) }))
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(300, JSONObject.NULL).apply { remove("signature") }))
        val foreign = manifest(300, JSONObject.NULL, otherSigning.private as Ed25519PrivateKeyParameters)
        assertNull(PinnedTls.fromManifest(server, 200, 0, foreign))
        val flagged = PinnedTls.fromManifest(server, 200, 0, manifest(310, JSONObject().put("off", true)))
        assertNotNull(flagged)
        assertNull(flagged?.tls)
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(310, JSONObject().put("off", false))))
        assertNull(PinnedTls.fromManifest(server, 200, 0, manifest(310, JSONObject().put("off", "true"))))
        Api.useTls(off?.tls)
        plainServer.enqueue(MockResponse().setBody("""{"ok":true}"""))
        assertTrue(Api.ping("agent").getBoolean("ok"))
        assertEquals(0, tlsServer.requestCount)
    }

    @Test
    fun unsignedOrForeignManifestChangesNothing() {
        val newPin = tls(PinnedTls.pinOf(newCert.certificate))
        val unsigned = manifest(500, newPin).apply { remove("signature") }
        assertNull(PinnedTls.fromManifest(server, 0, 0, unsigned))
        val tampered = manifest(500, newPin).apply { put("issued", 900) }
        assertNull(PinnedTls.fromManifest(server, 0, 0, tampered))
        val foreign = manifest(500, null, otherSigning.private as Ed25519PrivateKeyParameters)
        assertNull(PinnedTls.fromManifest(server, 0, 0, foreign))
        assertNull(PinnedTls.fromManifest(server, 0, 0, null))
        val broken = manifest(500, JSONObject().put("port", "8788").put("pin", PinnedTls.pinOf(newCert.certificate)))
        assertNull(PinnedTls.fromManifest(server, 0, 0, broken))
    }

    @Test
    fun recoveryRequestSendsNothingAndIgnoresRedirects() {
        plainServer.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "http://$HOST:${tlsServer.port}/x"))
        try {
            Api.manifestOverHttp()
            fail("redirect must not be followed")
        } catch (e: IOException) {
            assertTrue(e is Api.HttpError)
        }
        val request = plainServer.takeRequest()
        assertEquals("/v1/manifest", request.path)
        assertEquals(0L, request.bodySize)
        assertEquals(0, tlsServer.requestCount)
    }

    @Test
    fun qrWithPinSetsTls() {
        val pin = PinnedTls.pinOf(newCert.certificate)
        val params = mapOf("server" to "http://203.0.113.5:8787", "key" to "a".repeat(64), "tp" to "8788", "pin" to pin.replace('+', ' '))
        val target = Pairing.parse { params[it] }
        assertEquals("https://203.0.113.5:8788", target?.tls?.base)
        assertEquals(pin, target?.tls?.pin)
        val plain = Pairing.parse { mapOf("server" to "http://203.0.113.5:8787")[it] }
        assertNotNull(plain)
        assertNull(plain?.tls)
        assertNull(Pairing.parse { (params + ("tp" to "0"))[it] })
        assertNull(Pairing.parse { (params + ("pin" to "sha256/short="))[it] })
        assertNull(Pairing.parse { (params - "pin")[it] })
        assertNull(Pairing.parse { (params - "tp")[it] })
        assertEquals(0L, target?.issued)
        assertEquals(1_790_671_953L, Pairing.parse { (params + ("ti" to "1790671953"))[it] }?.issued)
        assertEquals(500L, Pairing.parse { mapOf("server" to "http://203.0.113.5:8787", "ti" to "500")[it] }?.issued)
        for (bad in listOf("", "-1", "12x", "1e9", "9".repeat(16))) assertNull(Pairing.parse { (params + ("ti" to bad))[it] })
    }

    @Test
    fun qrIssuedProtectsFreshlyPairedAgent() {
        val newPin = PinnedTls.pinOf(newCert.certificate)
        val params = mapOf("server" to server, "tp" to tlsServer.port.toString(), "pin" to newPin, "ti" to "500")
        val target = requireNotNull(Pairing.parse { params[it] })
        val fresh = Pairing.next(Pairing.Stored(null, 0, 0), target, sameServer = false, keyChanged = false)
        assertEquals(newPin, fresh.tls?.pin)
        assertEquals(500L, fresh.tlsIssued)
        assertEquals(500L, fresh.manifestIssued)
        Api.useTls(fresh.tls)
        tlsServer.shutdown()
        try {
            Api.ping("agent")
            fail("closed TLS port must fail")
        } catch (e: IOException) {
            assertTrue(PinnedTls.needsRecovery(e))
        }
        val oldPin = tls(PinnedTls.pinOf(oldCert.certificate))
        for (old in listOf(manifest(400, null), manifest(400, JSONObject.NULL), manifest(400, oldPin))) {
            plainServer.enqueue(MockResponse().setBody(JSONObject().put("manifest", old).toString()))
            assertNull(PinnedTls.fromManifest(server, fresh.tlsIssued, fresh.manifestIssued, Api.manifestOverHttp()))
        }
        assertNull(PinnedTls.fromManifest(server, fresh.tlsIssued, fresh.manifestIssued, manifest(500, JSONObject.NULL)))
        assertNull(PinnedTls.fromManifest(server, fresh.tlsIssued, fresh.manifestIssued, manifest(600, null)))
        val off = PinnedTls.fromManifest(server, fresh.tlsIssued, fresh.manifestIssued, manifest(600, JSONObject.NULL))
        assertNotNull(off)
        assertNull(off?.tls)
        val legacy = Pairing.next(Pairing.Stored(null, 0, 0), target.copy(issued = 0), sameServer = false, keyChanged = false)
        assertNull(PinnedTls.fromManifest(server, legacy.tlsIssued, legacy.manifestIssued, manifest(400, null)))
    }

    @Test
    fun rescanOfTheSameServerKeepsTlsAndBoundary() {
        val pinned = PinnedTls(HOST, tlsServer.port, PinnedTls.pinOf(newCert.certificate))
        val stored = Pairing.Stored(pinned, 700, 700)
        val plain = requireNotNull(Pairing.parse { mapOf("server" to server)[it] })
        val kept = Pairing.next(stored, plain, sameServer = true, keyChanged = false)
        assertEquals(pinned, kept.tls)
        assertEquals(700L, kept.tlsIssued)
        assertEquals(700L, kept.manifestIssued)
        assertNull(Pairing.next(stored, plain, sameServer = false, keyChanged = false).tls)
        val sameQr = requireNotNull(
            Pairing.parse { mapOf("server" to server, "tp" to pinned.port.toString(), "pin" to pinned.pin, "ti" to "500")[it] },
        )
        assertEquals(700L, Pairing.next(stored, sameQr, sameServer = true, keyChanged = false).tlsIssued)
        val boundary = Pairing.next(Pairing.Stored(null, 0, 0), plain.copy(issued = 800), sameServer = false, keyChanged = false)
        assertEquals(799L, boundary.tlsIssued)
        assertEquals(800L, boundary.manifestIssued)
        assertNotNull(PinnedTls.fromManifest(server, boundary.tlsIssued, boundary.manifestIssued, manifest(800, tls(pinned.pin)))?.tls)
        assertNull(PinnedTls.fromManifest(server, boundary.tlsIssued, boundary.manifestIssued, manifest(790, tls(pinned.pin))))
    }

    private fun tls(pin: String): JSONObject = JSONObject().put("port", tlsServer.port).put("pin", pin)

    private fun manifest(
        issued: Long,
        tls: Any?,
        key: Ed25519PrivateKeyParameters = signing.private as Ed25519PrivateKeyParameters,
    ): JSONObject {
        val manifest = JSONObject().put("issued", issued).put("note", "проверка")
        if (tls != null) manifest.put("tls", tls)
        val message = Verify.canonical(manifest).toByteArray(Charsets.UTF_8)
        val signer = Ed25519Signer().apply { init(true, key) }
        signer.update(message, 0, message.size)
        return manifest.put("signature", hex(signer.generateSignature()))
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private companion object {
        const val HOST = "127.0.0.1"
    }
}
