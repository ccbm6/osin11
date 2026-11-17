package com.personal.recon

import android.app.Application
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*

class ToolState {
    var busy by mutableStateOf(false)
    var status by mutableStateOf("")
    var lines by mutableStateOf<List<String>>(emptyList())
}

class Vm(app: Application) : AndroidViewModel(app) {
    private val store = Store(app)

    var target by mutableStateOf("")
    var shodanKey by mutableStateOf(store.key("shodan"))
    var hunterKey by mutableStateOf(store.key("hunter"))
    var vtKey by mutableStateOf(store.key("vt"))

    val subs = ToolState()
    val mails = ToolState()
    val info = ToolState()
    val shodan = ToolState()
    val history = mutableStateListOf<Scan>()

    init {
        viewModelScope.launch {
            val l = withContext(Dispatchers.IO) { store.load() }
            history.addAll(l)
        }
    }

    fun saveKeys(s: String, h: String, v: String) {
        shodanKey = s.trim(); hunterKey = h.trim(); vtKey = v.trim()
        store.setKey("shodan", shodanKey); store.setKey("hunter", hunterKey); store.setKey("vt", vtKey)
    }

    private fun domain(): String = target.trim().lowercase()
        .removePrefix("http://").removePrefix("https://")
        .substringBefore("/").substringBefore(":").removePrefix("www.")

    private val domainRx = Regex("^([a-z0-9-]+\\.)+[a-z]{2,}$")
    private fun validDomain(d: String) = domainRx.matches(d)

    private fun launchTool(t: ToolState, block: suspend (ToolState) -> Unit) {
        if (t.busy) return
        t.busy = true; t.lines = emptyList(); t.status = "جارٍ العمل…"
        viewModelScope.launch {
            try { block(t) } catch (e: Exception) { t.status = "خطأ: ${e.message ?: e.javaClass.simpleName}" }
            finally { t.busy = false }
        }
    }

    // ── نطاقات فرعية ──
    fun runSubs(live: Boolean) = launchTool(subs) { t ->
        val d = domain()
        if (!validDomain(d)) { t.status = "أدخل نطاقاً صحيحاً مثل example.com"; return@launchTool }
        val res = Api.subdomains(d, shodanKey, vtKey)
        val all = res.flatMap { it.hosts }.toSortedSet()
        val ok = res.filter { it.error == null }.joinToString(" ") { "${it.name}:${it.hosts.size}" }
        val bad = res.filter { it.error != null }.joinToString(" ") { "${it.name}(${it.error})" }
        val note = ok + (if (bad.isNotBlank()) "\nفشل: $bad" else "")
        if (live) {
            t.status = "تحليل ${all.size} اسم…"
            val m = withContext(Dispatchers.IO) { Api.resolve(all) }
            t.lines = m.toSortedMap().map { "${it.key}  →  ${it.value}" }
            t.status = "${m.size} حيّ من ${all.size}\n$note"
        } else {
            t.lines = all.toList()
            t.status = "${all.size} نتيجة\n$note"
        }
    }

    // ── بريد (theHarvester) ──
    fun runEmails() = launchTool(mails) { t ->
        val d = domain()
        if (!validDomain(d)) { t.status = "أدخل نطاقاً صحيحاً"; return@launchTool }
        val out = sortedSetOf<String>()
        val notes = mutableListOf<String>()
        withContext(Dispatchers.IO) {
            try { out += Api.siteEmails(d) } catch (e: Exception) { notes += "الموقع: ${e.message}" }
            if (hunterKey.isNotBlank()) {
                try { out += Api.hunter(d, hunterKey) } catch (e: Exception) { notes += "Hunter: ${e.message}" }
            } else notes += "أضف مفتاح Hunter من ⚙ لنتائج أكثر"
            Unit
        }
        t.lines = out.toList()
        t.status = "${out.size} نتيجة" + (if (notes.isNotEmpty()) "\n" + notes.joinToString("\n") else "")
    }

    // ── DNS + WHOIS ──
    fun runInfo() = launchTool(info) { t ->
        val d = domain()
        if (!validDomain(d)) { t.status = "أدخل نطاقاً صحيحاً"; return@launchTool }
        coroutineScope {
            val dns = async(Dispatchers.IO) { runCatching { Api.dns(d) } }
            val rd = async(Dispatchers.IO) { runCatching { Api.rdap(d) } }
            val a = dns.await(); val b = rd.await()
            val out = mutableListOf("── DNS ──")
            out += a.getOrElse { listOf("خطأ: ${it.message}") }
            out += ""
            out += "── WHOIS (RDAP) ──"
            out += b.getOrElse { listOf("خطأ: ${it.message}") }
            t.lines = out
            t.status = "تم"
        }
    }

    // ── Shodan ──
    fun runShodan() = launchTool(shodan) { t ->
        val d = domain()
        if (shodanKey.isBlank()) { t.status = "أدخل مفتاح Shodan من ⚙"; return@launchTool }
        if (!Api.isIp(d) && !validDomain(d)) { t.status = "أدخل نطاقاً أو IP صحيحاً"; return@launchTool }
        val out = mutableListOf<String>()
        withContext(Dispatchers.IO) {
            val ips = Api.resolveIps(d)
            if (ips.isEmpty()) out += "تعذّر تحليل الاسم إلى IP"
            for (ip in ips) {
                try { out += Api.shodanHost(ip, shodanKey) }
                catch (e: Exception) {
                    out += when (e.message) {
                        "HTTP 404" -> "$ip: لا توجد معلومات في Shodan"
                        "HTTP 401" -> "$ip: مفتاح Shodan غير صحيح"
                        else -> "$ip: ${e.message}"
                    }
                }
                out += ""
            }
        }
        t.lines = out
        t.status = "تم"
    }

    // ── السجل المشفّر ──
    fun save(type: String, t: ToolState) {
        if (t.lines.isEmpty()) return
        history.add(0, Scan(System.currentTimeMillis(), type, domain(), t.lines))
        persist()
    }

    fun delete(s: Scan) { history.remove(s); persist() }

    private fun persist() {
        val snap = history.toList()
        viewModelScope.launch(Dispatchers.IO) { store.save(snap) }
    }
}
