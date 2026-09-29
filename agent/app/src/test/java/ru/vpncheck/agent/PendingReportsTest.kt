package ru.vpncheck.agent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingReportsTest {
    @Test
    fun clockMovedBackKeepsReport() {
        val now = 1_800_000_000_000L
        assertTrue(PendingReports.isFresh(now + 3_600_000L, now))
        assertTrue(PendingReports.isFresh(now - 60_000L, now))
        assertFalse(PendingReports.isFresh(now - 13 * 3_600_000L, now))
        assertFalse(PendingReports.isFresh(0L, now))
        assertTrue(PendingReports.isFresh(now + 24 * 3_600_000L, now))
        assertFalse(PendingReports.isFresh(now + 25 * 3_600_000L, now))
    }
}
