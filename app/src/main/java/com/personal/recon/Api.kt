package com.personal.recon

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.TimeUnit

data class SourceResult(val name: String, val hosts: Set<String>, val error: String?)

object Api {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .callTimeout(60, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            chain.proceed(
                chain.request().newBuilder()
                    .header("User-Agent", "Mozilla/5.0 (Linux; Android 13) Recon/2.0").build()
            )
        }.build()

    fun get(url: String, headers: Map<String, String> = emptyMap()): String {
        val b = Request.Builder().url(url)
        headers.forEach { (k, v) -> b.header(k, v) }
        return http.newCall(b.build()).execute().use { r ->
            val body = r.body?.string().orEmpty()
            if (!r.isSuccessful) throw IllegalStateException("HTTP ${r.code}")
            body
        }
    }

    private val hostRx = Regex("^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")

    private fun clean(domain: String, raw: Collection<String>): Set<String> =
        raw.map { it.trim().lowercase().removePrefix("*.").trimEnd('.') }
            .filter { (it == domain || it.endsWith(".$domain")) && hostRx.matches(it) }
            .toSet()

    // ───────────── النطاقات الفرعية (Subfinder / Amass passive) ─────────────

    private class Src(val name: String, val run: () -> Set<String>)

    suspend fun subdomains(domain: String, shodanKey: String, vtKey: String): List<SourceResult> = coroutineScope {
        val src = mutableListOf(
            Src("crt.sh") { crt(domain) },
            Src("HackerTarget") { hackerTarget(domain) },
            Src("OTX") { otx(domain) },
            Src("Anubis") { anubis(domain) }
        )
        if (shodanKey.isNotBlank()) src += Src("Shodan") { shodanSubs(domain, shodanKey) }
        if (vtKey.isNotBlank()) src += Src("VirusTotal") { vtSubs(domain, vtKey) }
        src.map { s ->
            async(Dispatchers.IO) {
                try {
                    SourceResult(s.name, clean(domain, s.run()), null)
                } catch (e: Exception) {
                    SourceResult(s.name, emptySet(), e.message ?: e.javaClass.simpleName)
                }
            }
        }.awaitAll()
    }

    private fun crt(domain: String): Set<String> {
        val arr = JSONArray(get("https://crt.sh/?q=%25.$domain&output=json"))
        val out = mutableSetOf<String>()
        for (i in 0 until arr.length()) {
            arr.getJSONObject(i).optString("name_value").split("\n").forEach { out += it }
        }
        return out
    }

    private fun hackerTarget(domain: String): Set<String> {
        val t = get("https://api.hackertarget.com/hostsearch/?q=$domain")
        if (t.startsWith("error", true) || t.contains("API count exceeded", true))
            throw IllegalStateException(t.take(60))
        return t.lines().map { it.substringBefore(",") }.toSet()
    }

    private fun otx(domain: String): Set<String> {
        val a = JSONObject(get("https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns"))
            .optJSONArray("passive_dns") ?: JSONArray()
        return (0 until a.length()).map { a.getJSONObject(it).optString("hostname") }.toSet()
    }

    private fun anubis(domain: String): Set<String> {
        val a = JSONArray(get("https://jldc.me/anubis/subdomains/$domain"))
        return (0 until a.length()).map { a.getString(it) }.toSet()
    }

    private fun shodanSubs(domain: String, key: String): Set<String> {
        val a = JSONObject(get("https://api.shodan.io/dns/domain/$domain?key=$key"))
            .optJSONArray("subdomains") ?: JSONArray()
        return (0 until a.length()).map { "${a.getString(it)}.$domain" }.toSet()
    }

    private fun vtSubs(domain: String, key: String): Set<String> {
        val out = mutableSetOf<String>()
        var cursor: String? = null
        for (page in 0 until 5) {
            val url = "https://www.virustotal.com/api/v3/domains/$domain/subdomains?limit=40" +
                (cursor?.let { "&cursor=$it" } ?: "")
            val o = JSONObject(get(url, mapOf("x-apikey" to key)))
            val d = o.optJSONArray("data") ?: JSONArray()
            for (i in 0 until d.length()) out += d.getJSONObject(i).getString("id")
            cursor = o.optJSONObject("meta")?.optString("cursor")?.takeIf { it.isNotBlank() }
            if (cursor == null) break
        }
        return out
    }

    /** يحلّ الأسماء بالتوازي ويُبقي الحيّ منها فقط */
    suspend fun resolve(hosts: Collection<String>): Map<String, String> = coroutineScope {
        val gate = Semaphore(30)
        hosts.map { h ->
            async(Dispatchers.IO) {
                gate.withPermit {
                    try { h to (InetAddress.getByName(h).hostAddress ?: "") } catch (e: Exception) { null }
                }
            }
        }.awaitAll().filterNotNull().toMap()
    }

    // ───────────── البريد والموظفون (theHarvester) ─────────────

    private val emailRx = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")

    /** يقرأ صفحات الموقع العامة ويستخرج عناوين البريد المنشورة */
    fun siteEmails(domain: String): Set<String> {
        val out = sortedSetOf<String>()
        for (p in listOf("", "/contact", "/contact-us", "/about", "/about-us")) {
            try {
                val html = get("https://$domain$p")
                emailRx.findAll(html).map { it.value.lowercase() }
                    .filter { !it.endsWith(".png") && !it.endsWith(".jpg") && !it.endsWith(".webp") && !it.endsWith(".svg") }
                    .forEach { out += it }
            } catch (_: Exception) { }
        }
        return out
    }

    fun hunter(domain: String, key: String): List<String> {
        val data = JSONObject(get("https://api.hunter.io/v2/domain-search?domain=$domain&limit=100&api_key=$key"))
            .getJSONObject("data")
        val a = data.optJSONArray("emails") ?: JSONArray()
        return (0 until a.length()).map {
            val e = a.getJSONObject(it)
            val pos = e.optString("position")
            val name = listOf(e.optString("first_name"), e.optString("last_name")).filter { s -> s.isNotBlank() }.joinToString(" ")
            e.getString("value") + listOf(name, pos).filter { s -> s.isNotBlank() && s != "null" }
                .let { l -> if (l.isEmpty()) "" else "  (" + l.joinToString(" • ") + ")" }
        }
    }

    // ───────────── DNS و WHOIS ─────────────

    private val dnsTypes = linkedMapOf("A" to 1, "AAAA" to 28, "CNAME" to 5, "MX" to 15, "NS" to 2, "TXT" to 16, "SOA" to 6, "CAA" to 257)

    fun dns(domain: String): List<String> {
        val out = mutableListOf<String>()
        for ((name, code) in dnsTypes) {
            try {
                val a = JSONObject(get("https://dns.google/resolve?name=$domain&type=$name")).optJSONArray("Answer")
                    ?: continue
                for (i in 0 until a.length()) {
                    val x = a.getJSONObject(i)
                    if (x.optInt("type") == code) out += "${name.padEnd(6)} ${x.optString("data")}"
                }
            } catch (_: Exception) { }
        }
        return out
    }

    fun rdap(domain: String): List<String> {
        val o = JSONObject(get("https://rdap.org/domain/$domain"))
        val out = mutableListOf<String>()
        o.optJSONArray("status")?.let { s ->
            out += "الحالة: " + (0 until s.length()).joinToString(", ") { s.getString(it) }
        }
        o.optJSONArray("events")?.let { ev ->
            for (i in 0 until ev.length()) {
                val e = ev.getJSONObject(i)
                out += "${e.optString("eventAction")}: ${e.optString("eventDate")}"
            }
        }
        o.optJSONArray("nameservers")?.let { ns ->
            for (i in 0 until ns.length()) out += "NS: " + ns.getJSONObject(i).optString("ldhName")
        }
        o.optJSONArray("entities")?.let { en ->
            for (i in 0 until en.length()) {
                val e = en.getJSONObject(i)
                val roles = e.optJSONArray("roles")?.toString().orEmpty()
                if (roles.contains("registrar")) {
                    val vc = e.optJSONArray("vcardArray")?.optJSONArray(1)
                    if (vc != null) for (j in 0 until vc.length()) {
                        val item = vc.optJSONArray(j) ?: continue
                        if (item.optString(0) == "fn") out += "المسجّل: " + item.optString(3)
                    }
                }
            }
        }
        return out
    }

    // ───────────── Shodan ─────────────

    private val ipRx = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    fun isIp(s: String) = ipRx.matches(s)

    fun resolveIps(target: String): List<String> {
        if (isIp(target)) return listOf(target)
        return InetAddress.getAllByName(target).filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }.distinct().take(5)
    }

    fun shodanHost(ip: String, key: String): List<String> {
        val o = JSONObject(get("https://api.shodan.io/shodan/host/$ip?key=$key"))
        fun arr(name: String): String {
            val a = o.optJSONArray(name) ?: return "-"
            return (0 until a.length()).joinToString(", ") { a.get(it).toString() }.ifBlank { "-" }
        }
        val out = mutableListOf(
            "IP: $ip",
            "المنظمة: ${o.optString("org")}",
            "ISP: ${o.optString("isp")}",
            "الموقع: ${o.optString("country_name")} ${o.optString("city")}",
            "النظام: ${o.optString("os").takeIf { it != "null" } ?: "-"}",
            "Hostnames: ${arr("hostnames")}",
            "المنافذ: ${arr("ports")}",
            "الثغرات: ${arr("vulns")}"
        )
        val d = o.optJSONArray("data") ?: JSONArray()
        for (i in 0 until d.length()) {
            val s = d.getJSONObject(i)
            out += "  ${s.optInt("port")}/${s.optString("transport")}  " +
                listOf(s.optString("product"), s.optString("version")).filter { it.isNotBlank() }.joinToString(" ")
        }
        return out
    }
}
