package ru.vpncheck.agent

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.tls.decodeCertificatePem
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.InetAddress

class ServerTlsTest {
    private val held = HeldCertificate.Builder().commonName(HOST).addSubjectAlternativeName(HOST).ecdsa256().build()
    private val tlsServer = MockWebServer()
    private val plainServer = MockWebServer()

    @Before
    fun start() {
        tlsServer.useHttps(HandshakeCertificates.Builder().heldCertificate(held).build().sslSocketFactory(), false)
        tlsServer.start(InetAddress.getByName(HOST), 0)
        plainServer.start(InetAddress.getByName(HOST), 0)
        Api.base = "http://$HOST:${plainServer.port}"
    }

    @After
    fun stop() {
        Api.useTls(null)
        tlsServer.shutdown()
        plainServer.shutdown()
    }

    @Test
    fun pinMatchesOpenssl() {
        assertEquals(OPENSSL_PIN, PinnedTls.pinOf(CERT_PEM.decodeCertificatePem()))
    }

    @Test
    fun pinnedServerAnswers() {
        tlsServer.enqueue(MockResponse().setBody("""{"ok":true}"""))
        Api.useTls(PinnedTls(HOST, tlsServer.port, PinnedTls.pinOf(held.certificate)))
        assertEquals("https://$HOST:${tlsServer.port}", Api.root())
        assertTrue(Api.ping("agent").getBoolean("ok"))
        assertEquals("/v1/ping?agent_id=agent", tlsServer.takeRequest().path)
        assertEquals(0, plainServer.requestCount)
    }

    @Test
    fun wrongPinIsRefusedWithoutHttpFallback() {
        plainServer.enqueue(MockResponse().setBody("""{"ok":true}"""))
        Api.useTls(PinnedTls(HOST, tlsServer.port, "sha256/" + "A".repeat(43) + "="))
        try {
            Api.ping("agent")
            fail("pin mismatch must fail")
        } catch (e: IOException) {
            assertTrue(PinnedTls.isPinFailure(e))
        }
        assertEquals(0, plainServer.requestCount)
    }

    @Test
    fun withoutTlsStaysOnHttp() {
        plainServer.enqueue(MockResponse().setBody("""{"ok":true}"""))
        assertEquals(Api.base, Api.root())
        assertTrue(Api.ping("agent").getBoolean("ok"))
        assertEquals(0, tlsServer.requestCount)
    }

    @Test
    fun parseChecksPortAndPin() {
        val server = "http://203.0.113.5:8787"
        val good = PinnedTls.parse(server, JSONObject().put("port", 8788).put("pin", OPENSSL_PIN))
        assertNotNull(good)
        assertEquals("https://203.0.113.5:8788", good?.base)
        assertNull(PinnedTls.parse(server, JSONObject().put("port", 0).put("pin", OPENSSL_PIN)))
        assertNull(PinnedTls.parse(server, JSONObject().put("port", 8788.5).put("pin", OPENSSL_PIN)))
        assertNull(PinnedTls.parse(server, JSONObject().put("port", "8788").put("pin", OPENSSL_PIN)))
        assertNull(PinnedTls.parse(server, JSONObject().put("port", 8788).put("pin", OPENSSL_PIN.removePrefix("sha256/"))))
        assertNull(PinnedTls.parse(server, null))
        assertFalse(PinnedTls.isPinFailure(IOException("plain")))
    }

    @Test
    fun manifestWithTlsSignedByStandVerifies() {
        val previous = Verify.manifestKey
        try {
            Verify.manifestKey = STAND_PUB
            val manifest = JSONObject(STAND_MANIFEST)
            assertTrue(Verify.manifestSigned(manifest))
            val tls = PinnedTls.parse("http://203.0.113.5:8787", manifest.getJSONObject("tls"))
            assertEquals(8788, tls?.port)
            manifest.getJSONObject("tls").put("port", 8789)
            assertFalse(Verify.manifestSigned(manifest))
        } finally {
            Verify.manifestKey = previous
        }
    }

    private companion object {
        const val HOST = "127.0.0.1"
        const val OPENSSL_PIN = "sha256/LhTcBPd5VVvCWxJt6RJHBgBoGeb0MRKTO4dDF329cmw="
        const val CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUdPZMK1SrDd8wOprJsl26quFBK7owCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDkyOTA3MDYyNFoXDTM2MDkyNjA3
MDYyNFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEnmJRm85jiAM0xFI4xLcSVKMk+/ZAo4M1TsTMKpV+X51XRPyh3duJiUrO
TqxEAUsvvNBURhqQq+BzVeeNRvt5haNTMFEwHQYDVR0OBBYEFGEaykkX+iJrJCHH
xzhXudNs7u8ZMB8GA1UdIwQYMBaAFGEaykkX+iJrJCHHxzhXudNs7u8ZMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKyky7//ww9FFXpIUlChRvoM
3H4HIQClPJNJyRwhDtz9AiA2KNAcVcMv91MeFLh3nwC/54arSpRLW4XikJbbJphb
Jg==
-----END CERTIFICATE-----
"""
        const val STAND_PUB = "81a5da4ffd8b09f923712b394cd9cd9edbbba3955aa040e55fe32d47c6ab8d98"
        const val STAND_MANIFEST = """{"app": {"version_code": 37, "version_name": "0.12.9", "url": "/files/agent-0.12.9.apk",
            "sha256": "abababababababababababababababababababababababababababababababab"}, "issued": 1790000000,
            "note": "Проверка «ёж»", "tls": {"port": 8788, "pin": "sha256/q+/Zm0kVfJxN8TqB2WcP1yHwQn8E4cM2vK9oLrT3sDg="},
            "signature": "336e81f8cc88929c2796cfc6bf81c832ccdf2a9c3e50e68c6116369ee2762aad496e17393e7a47874bed1160c45b834bb8041a094ac612ac8798cd9a3a62ae03"}"""
    }
}
