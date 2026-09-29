package ru.vpncheck.agent

import android.content.Context
import android.net.Network
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

class CheckWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    private class Plan(config: JSONObject) {
        val nodes: JSONArray = config.optJSONArray("nodes") ?: JSONArray()
        val sites: JSONArray = config.optJSONArray("sites") ?: JSONArray()
        val testUrl: String = safeUrl(config.text("test_url"), "https://api.ipify.org")
        val latencyUrl: String = safeUrl(config.text("latency_url"), "https://www.google.com/generate_204")
        val manifest: JSONObject? = config.optJSONObject("manifest")
    }

    private class Session(val ctx: Context, val prefs: Prefs, val plan: Plan) {
        val runner = XrayRunner(ctx)
        @Volatile var rejectedCode = 0
    }

    private class NetPass(
        val session: Session,
        val net: Network,
        val gather: NetGather,
        val wifiIp: String,
        val endsAt: Long,
    ) {
        val ctx = session.ctx
        val prefs = session.prefs
        val plan = session.plan
        val runner = session.runner
        val startedAt = System.currentTimeMillis()
        val netDesc: JSONObject = NetInfo.describe(ctx, net)
        val type: String = netDesc.text("type")
        val vpn: Boolean = NetInfo.vpnActive(ctx)

        fun lost(): Boolean = gather.isLost(net)
    }

    private class Direct(
        val ok: Boolean,
        val exitIp: String,
        val sameAsWifi: Boolean,
        val routeMismatch: Boolean,
        val source: XrayRunner.Via?,
        val blind: String?,
        val core: CoreProbe?,
    ) {
        val via: XrayRunner.Via? get() = core?.via
        val coreOk: Boolean get() = core?.outcome?.ok == true
        val bind: String get() = when {
            via?.device != null -> "device"
            via != null -> "ip"
            else -> "none"
        }
    }

    private class CoreProbe(val outcome: XrayRunner.Outcome, val via: XrayRunner.Via?, val log: String)

    private inner class NodeCheck(val pass: NetPass, val via: XrayRunner.Via?, val retry: Boolean, val deadline: Long) {
        val results = JSONObject()
        val confirmed = HashSet<String>()
        val pins = ConcurrentHashMap<String, Map<String, List<String>>>()
        var rejected = 0
        var coreFailed = 0
        var blind = 0

        fun open(needMs: Long = 0L): Boolean = !isStopped && !pass.lost() && System.currentTimeMillis() + needMs < deadline
    }

    private class NodeRun(val results: JSONObject, val unchecked: Int, val rejected: Int, val coreFailed: Int, val blind: Int) {
        val notChecked: Int get() = unchecked + rejected + coreFailed + blind
    }

    private class SiteRun(val sites: JSONObject, val lines: String, val unchecked: Int)

    private class PassResult(val alive: Int, val checked: Int, val notChecked: Int, val details: String, val exitIp: String)

    private enum class Delivery { SENT, DEFERRED, FAILED }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val ctx = applicationContext
        val prefs = Prefs(ctx)
        val once = inputData.getBoolean(Scheduler.KEY_ONCE, false)
        if (!prefs.consented || prefs.paused) return@withContext Result.success()
        if (!Api.paired()) {
            finish(prefs, ctx.getString(R.string.summary_not_paired))
            return@withContext Result.success()
        }
        if (!RUNNING.compareAndSet(false, true)) return@withContext Result.success()
        val workEnds = System.currentTimeMillis() + WORK_BUDGET_MS
        prefs.running = true
        prefs.lastSummary = ctx.getString(R.string.summary_running)
        try {
            val config = loadConfig(ctx, prefs) ?: return@withContext again(once)
            runChecks(ctx, prefs, Plan(config), once, workEnds)
        } catch (e: XrayRunner.CoreStartError) {
            ErrorLog.record(ctx, "core-start", e)
            finish(prefs, ctx.getString(R.string.summary_core_error, e.message.orEmpty().take(80)))
            Result.success()
        } catch (_: IOException) {
            finish(prefs, ctx.getString(R.string.summary_network_unavailable))
            Result.success()
        } catch (e: Exception) {
            ErrorLog.record(ctx, "check", e)
            finish(prefs, ctx.getString(R.string.summary_error, (e.message ?: e.javaClass.simpleName).take(80)))
            Result.success()
        } finally {
            prefs.running = false
            RUNNING.set(false)
        }
    }

    private fun fetchConfig(ctx: Context): JSONObject = try {
        Api.config(ctx)
    } catch (e: IOException) {
        if (e is Api.HttpError || !PinnedTls.needsRecovery(e) || Prefs(ctx).tls == null) throw e
        if (PinnedTls.isPinFailure(e)) ErrorLog.recordLimited(ctx, "tls-pin", e)
        if (!Updater(ctx).recoverTls()) throw e
        Api.evict()
        Api.config(ctx)
    }

    private fun loadConfig(ctx: Context, prefs: Prefs): JSONObject? {
        val config = try {
            Api.evict()
            fetchConfig(ctx)
        } catch (e: Api.HttpError) {
            ErrorLog.record(ctx, "check", e)
            finish(prefs, ctx.getString(R.string.summary_error, e.message.orEmpty().take(80)))
            return null
        } catch (e: IOException) {
            val pinFailed = PinnedTls.isPinFailure(e)
            if (pinFailed) ErrorLog.recordLimited(ctx, "tls-pin", e)
            finish(prefs, ctx.getString(if (pinFailed) R.string.summary_tls_mismatch else R.string.summary_network_unavailable))
            return null
        }
        prefs.serverMessage = config.text("message")
        val round = config.optDouble("location_round", 200.0)
        prefs.locRound = if (round.isFinite()) round.coerceIn(1.0, 5000.0).toFloat() else 200f
        Updater(ctx).learnTls(config.optJSONObject("manifest"))
        Scheduler.updateInterval(ctx, prefs, config.optInt("interval_min", prefs.intervalMin))
        try {
            PendingReports.flush(ctx)
        } catch (e: Exception) {
            ErrorLog.recordLimited(ctx, "report-deferred", e)
        }
        return config
    }

    private fun runChecks(ctx: Context, prefs: Prefs, plan: Plan, once: Boolean, workEnds: Long): Result {
        val gather = NetGather.request(ctx, 15000)
        if (gather.networks.isEmpty()) {
            gather.release()
            val behindVpn = NetInfo.describe(ctx).optBoolean("vpn")
            finish(prefs, ctx.getString(if (behindVpn) R.string.summary_vpn_no_direct else R.string.summary_no_network))
            applyUpdate(ctx, prefs, plan)
            if (behindVpn) {
                Scheduler.runLater(ctx, 30)
                return Result.success()
            }
            return again(once)
        }
        val summary = StringBuilder()
        val details = StringBuilder()
        val session = Session(ctx, prefs, plan)
        try {
            var wifiIp = ""
            val networks = gather.networks
            for ((index, net) in networks.withIndex()) {
                if (isStopped || remaining(workEnds) < NET_MIN_MS) break
                if (gather.isLost(net)) continue
                val share = remaining(workEnds) / (networks.size - index)
                val pass = NetPass(session, net, gather, wifiIp, System.currentTimeMillis() + share)
                val result = runPass(pass) ?: continue
                if (pass.type == "wifi" && result.exitIp.isNotEmpty()) wifiIp = result.exitIp
                val operator = if (pass.type == "cellular") pass.netDesc.text("operator") else ""
                val label = NetInfo.label(ctx, pass.type) + if (operator.isNotEmpty()) " $operator" else ""
                if (summary.isNotEmpty()) summary.append(" · ")
                summary.append(ctx.getString(R.string.pass_summary, label, result.alive, result.checked))
                if (result.notChecked > 0) summary.append(ctx.getString(R.string.pass_summary_unchecked, result.notChecked))
                details.append("- $label -\n").append(result.details).append('\n')
            }
        } finally {
            gather.release()
        }
        val rejectedCode = session.rejectedCode
        if (rejectedCode > 0) {
            if (summary.isNotEmpty()) summary.append(" · ")
            summary.append(ctx.getString(R.string.summary_report_rejected, rejectedCode))
        }
        if (summary.isEmpty()) {
            finish(prefs, ctx.getString(R.string.summary_no_network))
            return Result.success()
        }
        finish(prefs, summary.toString())
        prefs.editDetails { details.toString().trimEnd() }
        applyUpdate(ctx, prefs, plan)
        return Result.success()
    }

    private fun applyUpdate(ctx: Context, prefs: Prefs, plan: Plan) {
        Updater(ctx).apply(plan.manifest)?.let(prefs::addDetailLine)
    }

    private fun again(once: Boolean): Result = if (once) Result.failure() else Result.retry()

    private fun finish(prefs: Prefs, summary: String) {
        prefs.lastSummary = summary
        prefs.lastCheck = System.currentTimeMillis()
    }

    private fun runPass(pass: NetPass): PassResult? {
        val netClient = Api.clientFor(pass.net)
        val siteClient = SiteCheck.clientFor(pass.net)
        try {
            val direct = probeDirect(pass, siteClient) ?: return null
            if (direct.blind == NodeRules.CORE_DIRECT) {
                ErrorLog.recordLimited(
                    pass.ctx, NodeRules.CORE_DIRECT, null,
                    text = "xray direct probe failed (bind ${direct.bind}), plain request passed\n${direct.core?.log.orEmpty()}"
                )
            }
            val nodes = checkNodes(pass, direct)
            val sites = checkSites(pass, siteClient)
            if (pass.lost() || NetInfo.source(pass.ctx, pass.net) != direct.source) return null
            if (!pass.prefs.consented || pass.prefs.paused) return null
            val payload = buildPayload(pass, direct, nodes, sites)
            val delivery = deliver(pass, payload, netClient, direct.ok)
            if (delivery == Delivery.FAILED) return null
            val alive = nodes.results.keys().asSequence().count { nodes.results.optJSONObject(it)?.optBoolean("ok") == true }
            val checked = (pass.plan.nodes.length() - nodes.notChecked).coerceAtLeast(0)
            return PassResult(alive, checked, nodes.notChecked, passDetails(pass, direct, nodes, sites, delivery), direct.exitIp)
        } finally {
            netClient.connectionPool.evictAll()
            siteClient.connectionPool.evictAll()
        }
    }

    private fun probeDirect(pass: NetPass, siteClient: OkHttpClient): Direct? {
        val bound = NetInfo.source(pass.ctx, pass.net)
        val netIp = Api.fetchText(siteClient, pass.plan.testUrl)
        val core = if (pass.vpn) null else probeCore(pass, bound)
        if (pass.lost()) return null
        val coreOk = core?.outcome?.ok == true
        val coreIp = core?.outcome?.exitIp.orEmpty()
        val exitIp = coreIp.ifEmpty { netIp }
        return Direct(
            ok = coreOk || netIp.isNotEmpty(),
            exitIp = exitIp,
            sameAsWifi = pass.type == "cellular" && pass.wifiIp.isNotEmpty() && exitIp == pass.wifiIp,
            routeMismatch = coreOk && netIp.isNotEmpty() && coreIp != netIp,
            source = bound,
            blind = when {
                pass.vpn -> NodeRules.VPN
                !coreOk && netIp.isNotEmpty() -> NodeRules.CORE_DIRECT
                else -> null
            },
            core = core,
        )
    }

    private fun probeCore(pass: NetPass, bound: XrayRunner.Via?): CoreProbe {
        val plan = pass.plan
        val hosts = pinHosts(pass.net, bound != null, plan.testUrl, plan.latencyUrl)
        fun probe(via: XrayRunner.Via?) =
            pass.runner.check(null, plan.testUrl, plan.latencyUrl, waitMs = 7000, via = via, hosts = hosts)
        val first = probe(bound)
        if (first.ok || bound?.device == null || pass.lost()) return CoreProbe(first, bound, first.logTail)
        val loose = bound.copy(device = null)
        val second = probe(loose)
        if (second.ok) return CoreProbe(second, loose, "")
        return CoreProbe(first, bound, "--- device ${bound.device} ---\n${first.logTail}\n--- ip only ---\n${second.logTail}")
    }

    private fun pinHosts(net: Network, v4Only: Boolean, vararg urls: String): Map<String, List<String>> {
        val out = LinkedHashMap<String, List<String>>()
        for (url in urls) {
            val host = url.toHttpUrlOrNull()?.host ?: continue
            if (host in out || SiteCheck.literalAddress(host) != null) continue
            val found = SiteCheck.lookupWithin(XrayRunner.RESOLVE_MS) { net.getAllByName(host).toList() }
            val ips = found.mapNotNull { it.hostAddress?.substringBefore('%') }
            if (ips.isNotEmpty()) out[host] = ips
        }
        return NodeRules.preferV4(out, v4Only)
    }

    private fun buildPayload(pass: NetPass, direct: Direct, nodes: NodeRun, sites: SiteRun): JSONObject {
        val prefs = pass.prefs
        val vpnActive = pass.vpn || NetInfo.vpnActive(pass.ctx)
        if (vpnActive) pass.netDesc.put("vpn", true)
        return JSONObject().apply {
            put("report_id", UUID.randomUUID().toString())
            put("agent_id", prefs.agentId)
            put("app_version", BuildConfig.VERSION_NAME)
            put("app_version_code", BuildConfig.VERSION_CODE)
            put("core_version", pass.runner.coreVersion())
            put("device", JSONObject().put("model", Build.MODEL).put("android", Build.VERSION.RELEASE))
            put("network", pass.netDesc)
            if (prefs.locTs > 0L) put("location", locationJson(prefs))
            put("sites", sites.sites)
            if (sites.unchecked > 0) put("sites_unchecked", sites.unchecked)
            put("push_token", prefs.pushToken)
            put("direct_ok", direct.ok)
            put("direct_ip", direct.exitIp)
            put("bind", direct.bind)
            if (!pass.vpn) put("core_direct_ok", direct.coreOk)
            put("vpn_active", vpnActive)
            if (direct.sameAsWifi) put("same_ip_as", "wifi")
            if (direct.routeMismatch) put("route_mismatch", true)
            if (isStopped || nodes.unchecked > 0 || nodes.blind > 0) put("partial", true)
            if (nodes.unchecked > 0) put("unchecked", nodes.unchecked)
            val skipped = nodes.rejected + nodes.coreFailed + nodes.blind
            if (skipped > 0) put("rejected", skipped)
            if (nodes.coreFailed > 0) put("core_failed", nodes.coreFailed)
            NodeRules.uncheckedReasons(nodes.results, MAX_UNCHECKED_NODES)?.let { put("unchecked_nodes", it) }
            put("started", pass.startedAt / 1000)
            put("duration_s", (System.currentTimeMillis() - pass.startedAt) / 1000)
            put("results", nodes.results)
        }
    }

    private fun locationJson(prefs: Prefs): JSONObject = JSONObject().apply {
        put("lat", prefs.locLat.toDouble())
        put("lon", prefs.locLon.toDouble())
        put("city", prefs.locCity)
        put("region", prefs.locRegion)
        put("source", "coarse")
        put("accuracy", prefs.locAccuracy.toDouble())
        put("round", prefs.locRound.toDouble())
    }

    private fun deliver(pass: NetPass, payload: JSONObject, netClient: OkHttpClient, directOk: Boolean): Delivery {
        val ctx = pass.ctx
        if (isStopped) {
            PendingReports.save(ctx, payload)
            return Delivery.DEFERRED
        }
        val errors = ErrorLog.claim(ctx)
        payload.put("errors", errors)
        val answer = try {
            try {
                Api.report(payload, netClient)
            } catch (e: IOException) {
                if (directOk) throw e
                Api.report(payload.put("report_via", "default"))
            }
        } catch (e: IOException) {
            ErrorLog.release(errors)
            if (e is Api.HttpError) {
                ErrorLog.record(ctx, "report", e)
                if (e.code in 400..499 && e.code != 429) {
                    pass.session.rejectedCode = e.code
                    return Delivery.FAILED
                }
            }
            PendingReports.save(ctx, payload)
            return Delivery.DEFERRED
        } catch (e: Exception) {
            ErrorLog.release(errors)
            throw e
        }
        ErrorLog.forget(ctx, errors)
        val region = listOf(answer.text("city"), answer.text("region")).filter { it.isNotEmpty() }.joinToString(", ")
        if (region.isNotEmpty()) pass.prefs.lastRegion = region
        return Delivery.SENT
    }

    private fun passDetails(pass: NetPass, direct: Direct, nodes: NodeRun, sites: SiteRun, delivery: Delivery): String {
        val ctx = pass.ctx
        val out = StringBuilder(sites.lines)
        fun warn(text: String) = out.append("⚠ ").append(text).append('\n')
        when (direct.blind) {
            NodeRules.VPN -> warn(ctx.getString(R.string.pass_vpn_nodes))
            NodeRules.CORE_DIRECT -> warn(ctx.getString(R.string.pass_core_direct))
            else -> if (!direct.ok) warn(ctx.getString(R.string.pass_no_direct))
        }
        if (direct.sameAsWifi || direct.routeMismatch) warn(ctx.getString(R.string.pass_route_doubt))
        if (nodes.unchecked > 0) warn(ctx.getString(R.string.pass_unchecked, nodes.unchecked))
        if (delivery == Delivery.DEFERRED) warn(ctx.getString(R.string.pass_report_deferred))
        val plan = pass.plan
        for (i in 0 until plan.nodes.length()) {
            val node = plan.nodes.getJSONObject(i)
            val key = node.text("key")
            val result = nodes.results.optJSONObject(key) ?: continue
            val name = node.text("location", key).take(18)
            if (result.optBoolean("unchecked")) {
                val error = result.text("error")
                if (error == direct.blind) continue
                val reason = when {
                    error == NodeRules.UNSUPPORTED -> R.string.node_unsupported
                    error.startsWith(CORE_EXIT) -> R.string.node_core_exit
                    else -> R.string.node_rejected
                }
                out.append("⊘ ").append(name).append("  ").append(ctx.getString(reason)).append('\n')
                continue
            }
            val ok = result.optBoolean("ok")
            out.append(if (ok) "● " else "✕ ").append(name)
            if (!result.isNull("latency")) out.append("  ").append(ctx.getString(R.string.latency_ms, result.optLong("latency")))
            when (result.text("error")) {
                NodeRules.DNS_SINKHOLE -> out.append("  ").append(ctx.getString(R.string.node_dns_sinkhole))
                NodeRules.DNS_FAIL -> out.append("  ").append(ctx.getString(R.string.node_dns_fail))
            }
            out.append('\n')
        }
        return out.toString().trimEnd()
    }

    private fun checkSites(pass: NetPass, client: OkHttpClient): SiteRun {
        val list = pass.plan.sites
        if (list.length() == 0) return SiteRun(JSONObject(), "", 0)
        val deadline = System.currentTimeMillis() + minOf(SITE_BUDGET_MS, remaining(pass.endsAt) - DELIVER_RESERVE_MS).coerceAtLeast(0)
        val outcomes = arrayOfNulls<SiteCheck.Result>(list.length())
        val pool = Executors.newFixedThreadPool(PARALLEL)
        try {
            val tasks = (0 until list.length()).mapNotNull { i ->
                val url = list.getJSONObject(i).text("url")
                if (url.isEmpty()) return@mapNotNull null
                pool.submit {
                    if (isStopped || pass.lost() || System.currentTimeMillis() >= deadline) return@submit
                    outcomes[i] = SiteCheck.direct(url, client)
                }
            }
            awaitAll(tasks)
        } finally {
            pool.shutdownNow()
        }
        val sites = JSONObject()
        val lines = StringBuilder()
        var unchecked = 0
        for (i in 0 until list.length()) {
            val site = list.getJSONObject(i)
            val url = site.text("url")
            if (url.isEmpty()) continue
            val r = outcomes[i]
            if (r == null) {
                unchecked++
                continue
            }
            sites.put(url, JSONObject().put("ok", r.ok).put("code", r.code).put("ms", r.ms ?: JSONObject.NULL)
                .put("error", r.error))
            lines.append(if (r.ok) "🌐 " else "⛔ ").append(site.text("name", url).take(24))
            if (r.ok) lines.append("  ${r.code} · ").append(pass.ctx.getString(R.string.latency_ms, r.ms))
            else lines.append("  ").append(r.errorRes?.let { pass.ctx.getString(it) } ?: r.error)
            lines.append('\n')
        }
        return SiteRun(sites, lines.toString(), unchecked)
    }

    private fun checkNodes(pass: NetPass, direct: Direct): NodeRun {
        val left = remaining(pass.endsAt) - DELIVER_RESERVE_MS
        val siteReserve = if (pass.plan.sites.length() > 0) minOf(SITE_BUDGET_MS, left / 4) else 0L
        val deadline = System.currentTimeMillis() + minOf(NODE_BUDGET_MS, left - siteReserve).coerceAtLeast(0)
        val check = NodeCheck(pass, direct.via, retry = direct.ok, deadline = deadline)
        markRejected(check)
        direct.blind?.let { return settle(markBlind(check, it)) }
        val pool = Executors.newFixedThreadPool(PARALLEL)
        try {
            for (round in 0..(if (check.retry) 1 else 0)) {
                if (round == 1 && !check.open()) break
                runRound(pool, check, round)
                if (isStopped || pass.lost()) break
            }
        } finally {
            pool.shutdownNow()
        }
        return settle(check)
    }

    private fun markRejected(check: NodeCheck) {
        val nodes = check.pass.plan.nodes
        for (i in 0 until nodes.length()) {
            val node = nodes.getJSONObject(i)
            val refusal = check.pass.runner.refusal(node) ?: continue
            val key = node.text("key")
            check.results.put(key, JSONObject().put("ok", false).put("unchecked", true).put("error", refusal.code))
            check.confirmed.add(key)
            check.rejected++
        }
    }

    private fun markBlind(check: NodeCheck, reason: String): NodeCheck {
        val nodes = check.pass.plan.nodes
        for (i in 0 until nodes.length()) {
            val key = nodes.getJSONObject(i).text("key")
            if (check.results.has(key)) continue
            check.results.put(key, JSONObject().put("ok", false).put("unchecked", true).put("error", reason))
            check.confirmed.add(key)
            check.blind++
        }
        return check
    }

    private fun runRound(pool: ExecutorService, check: NodeCheck, round: Int) {
        val nodes = check.pass.plan.nodes
        val tasks = (0 until nodes.length()).mapNotNull { i ->
            val node = nodes.getJSONObject(i)
            if (!wanted(check, node.text("key"), round)) return@mapNotNull null
            pool.submit { checkOne(check, node, round) }
        }
        awaitAll(tasks)
    }

    private fun wanted(check: NodeCheck, key: String, round: Int): Boolean = synchronized(check.results) {
        val prior = check.results.optJSONObject(key)
        when {
            prior?.optBoolean("unchecked") == true -> false
            round == 0 -> prior == null
            else -> prior?.optBoolean("ok") == false && check.pins.containsKey(key)
        }
    }

    private fun checkOne(check: NodeCheck, node: JSONObject, round: Int) {
        val first = round == 0
        if (!check.open(if (first) FIRST_WORST_MS else RETRY_WORST_MS)) return
        val key = node.text("key")
        val plan = check.pass.plan
        val hosts = if (first) pin(check, node, key) ?: return else check.pins[key] ?: return
        val outcome = check.pass.runner.check(
            node, plan.testUrl, plan.latencyUrl, waitMs = if (first) 7000 else 14000,
            via = check.via, timeoutSec = if (first) 12 else 25, hosts = hosts
        )
        synchronized(check.results) {
            if (outcome.coreExit != null) {
                check.results.put(key, JSONObject().put("ok", false).put("unchecked", true).put("error", "$CORE_EXIT${outcome.coreExit}"))
                check.confirmed.add(key)
                check.coreFailed++
                return
            }
            if (first || outcome.ok) {
                check.results.put(key, JSONObject().put("ok", outcome.ok).put("latency", outcome.latencyMs ?: JSONObject.NULL))
            }
            if (!first || outcome.ok || !check.retry) check.confirmed.add(key)
        }
    }

    private fun pin(check: NodeCheck, node: JSONObject, key: String): Map<String, List<String>>? {
        val resolved = check.pass.runner.resolve(node) { host -> check.pass.net.getAllByName(host).toList() }
        val refusal = resolved.refusal
        val dead = resolved.dead
        if (refusal == null && dead == null && resolved.unanswered) return null
        if (refusal == null && dead == null) {
            return NodeRules.preferV4(resolved.hosts, check.via != null).also { check.pins[key] = it }
        }
        synchronized(check.results) {
            val result = if (refusal != null) {
                check.rejected++
                JSONObject().put("ok", false).put("unchecked", true).put("error", refusal.code)
            } else {
                JSONObject().put("ok", false).put("latency", JSONObject.NULL).put("error", dead)
            }
            check.results.put(key, result)
            check.confirmed.add(key)
        }
        return null
    }

    private fun settle(check: NodeCheck): NodeRun = synchronized(check.results) {
        val results = check.results
        val doubtful = results.keys().asSequence().filter { it !in check.confirmed }.toList()
        for (key in doubtful) results.remove(key)
        val unchecked = (check.pass.plan.nodes.length() - results.length()).coerceAtLeast(0)
        NodeRun(results, unchecked, check.rejected, check.coreFailed, check.blind)
    }

    private fun awaitAll(tasks: List<Future<*>>) {
        for (task in tasks) {
            try {
                task.get()
            } catch (e: ExecutionException) {
                throw e.cause ?: e
            }
        }
    }

    companion object {
        private const val PARALLEL = 3
        private const val WORK_BUDGET_MS = 6 * 60_000L
        private const val NODE_BUDGET_MS = 4 * 60_000L
        private const val SITE_BUDGET_MS = 60_000L
        private const val NET_MIN_MS = 90_000L
        private const val DELIVER_RESERVE_MS = 30_000L
        private const val CORE_EXIT = "core-exit:"
        private const val FIRST_WORST_MS = 42_000L
        private const val RETRY_WORST_MS = 70_000L
        private const val MAX_UNCHECKED_NODES = 300

        private fun remaining(until: Long): Long = (until - System.currentTimeMillis()).coerceAtLeast(0)

        private fun safeUrl(url: String, fallback: String): String =
            if (url.isNotEmpty() && SiteCheck.isPublicUrl(url, httpsOnly = true)) url else fallback
        private val RUNNING = AtomicBoolean(false)

        val active: Boolean get() = RUNNING.get()

        fun formatTime(ms: Long): String =
            if (ms == 0L) "-" else SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(Date(ms))
    }
}
