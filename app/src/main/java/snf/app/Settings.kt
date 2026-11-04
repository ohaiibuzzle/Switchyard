package snf.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class DnsPreset(val name: String, val url: String, val bootstrap: String)

val DNS_PRESETS = listOf(
    DnsPreset("Cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1,1.0.0.1"),
    DnsPreset("Cloudflare", "tls://one.one.one.one", "1.1.1.1,1.0.0.1"),
    DnsPreset("Quad9", "https://dns.quad9.net/dns-query", "9.9.9.9,149.112.112.112"),
    DnsPreset("AdGuard", "quic://dns.adguard-dns.com", "94.140.14.14,94.140.15.15"),
    DnsPreset("Google", "https://dns.google/dns-query", "8.8.8.8,8.8.4.4"),
)

/** Human-readable transport name for a resolver URL. */
fun dnsKind(url: String) = when (url.substringBefore("://")) {
    "https" -> "DNS over HTTPS"
    "h3" -> "DNS over HTTP/3"
    "tls" -> "DNS over TLS"
    "quic" -> "DNS over QUIC"
    else -> "Custom"
}

data class WgProfile(val name: String, val conf: String) {
    val endpoint get() = Regex("""(?im)^\s*Endpoint\s*=\s*(\S+)""").find(conf)?.groupValues?.get(1) ?: "No endpoint"
}

data class ListPreset(val name: String, val desc: String, val url: String)

val LIST_PRESETS = listOf(
    ListPreset("StevenBlack", "Balanced · ads and malware", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ListPreset("HaGeZi Pro", "Strict · ads, tracking and more", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"),
    ListPreset("OISD Small", "Light · fewest false blocks", "https://small.oisd.nl/"),
)

/** All settings live in one SharedPreferences file; [configJson] turns them into the core's config. */
class Settings(ctx: Context) {
    private val app = ctx.applicationContext
    val prefs = app.getSharedPreferences("snf", Context.MODE_PRIVATE)

    fun str(k: String, def: String = "") = prefs.getString(k, def)!!
    fun bool(k: String, def: Boolean = false) = prefs.getBoolean(k, def)
    fun set(k: String) = prefs.getStringSet(k, emptySet())!!.toSet()
    fun put(k: String, v: Any) {
        prefs.edit().apply {
            when (v) {
                is String -> putString(k, v)
                is Boolean -> putBoolean(k, v)
                is Set<*> -> putStringSet(k, v.map { it.toString() }.toSet())
            }
        }.apply()
    }

    /** Adds a domain rule; a domain is either allowed or blocked, never both. */
    fun addRule(allow: Boolean, domain: String) {
        val (to, from) = if (allow) "allowDomains" to "blockDomains" else "blockDomains" to "allowDomains"
        put(from, set(from) - domain)
        put(to, set(to) + domain)
    }

    fun toggleIn(k: String, item: String) = put(k, set(k).let { if (item in it) it - item else it + item })

    /** "off", "proxy" or "wg". Falls back to the pre-WireGuard proxyOn switch. */
    fun routeMode() = str("routeMode", if (bool("proxyOn")) "proxy" else "off")

    fun wgProfiles(): List<WgProfile> {
        val raw = prefs.getString("wgProfiles", null)
            // Pre-profiles installs kept a single config under "wgConf".
            ?: return str("wgConf").takeIf { it.isNotBlank() }?.let { listOf(WgProfile("WireGuard", it)) }.orEmpty()
        val a = JSONArray(raw)
        return List(a.length()) { a.getJSONObject(it).let { o -> WgProfile(o.getString("name"), o.getString("conf")) } }
    }

    fun activeWg() = wgProfiles().let { ps -> ps.firstOrNull { it.name == str("wgActive") } ?: ps.firstOrNull() }

    /** Replaces the profile named [old] (or appends), keeping list order. */
    fun saveWg(old: String?, p: WgProfile) {
        val list = wgProfiles().toMutableList()
        val i = list.indexOfFirst { it.name == old }
        if (i >= 0) list[i] = p else list += p
        writeWg(list)
    }

    fun deleteWg(name: String) = writeWg(wgProfiles().filter { it.name != name })

    // Also drops the pre-profiles "wgConf" copy, so deleting a profile really removes its key.
    private fun writeWg(list: List<WgProfile>) = prefs.edit()
        .putString("wgProfiles", JSONArray(list.map { JSONObject().put("name", it.name).put("conf", it.conf) }).toString())
        .remove("wgConf")
        .apply()

    fun dnsUrl() = str("dnsUrl", DNS_PRESETS[0].url)
    fun dnsBootstrap() = str("dnsBootstrap", DNS_PRESETS[0].bootstrap)

    fun listFile(url: String) = File(app.filesDir, "lists/%08x.txt".format(url.hashCode()))

    fun configJson(): String = JSONObject().apply {
        put("dnsUpstream", dnsUrl())
        put("dnsBootstrap", JSONArray(dnsBootstrap().split(',').map { it.trim() }.filter { it.isNotEmpty() }))
        put("blockedUids", JSONArray(set("blocked").map { it.toInt() }))
        put("blocklists", JSONArray(if (bool("adblock")) set("lists").map { listFile(it).path }.filter { File(it).exists() } else emptyList()))
        put("blockBypass", bool("blockBypass", true))
        put("sniSplit", bool("sniSplit"))
        put("tlsFrag", bool("tlsFrag"))
        put("hostTricks", bool("hostTricks"))
        put("blockQuic", bool("blockQuic"))
        put("proxyUrl", if (routeMode() == "proxy") str("proxyUrl") else "")
        put("wgConf", if (routeMode() == "wg") activeWg()?.conf.orEmpty() else "")
        put("routeUids", JSONArray(set("proxied").map { it.toInt() }))
        put("allowDomains", JSONArray(set("allowDomains").toList()))
        put("blockDomains", JSONArray(set("blockDomains").toList()))
        put("log", bool("logOn"))
    }.toString()

    /** Downloads lists that are missing or older than [maxAgeMs]. Returns per-URL errors. Blocking. */
    fun refreshLists(maxAgeMs: Long = 24 * 3600_000L): Map<String, String> {
        val errors = mutableMapOf<String, String>()
        for (url in set("lists")) {
            val f = listFile(url)
            if (f.exists() && System.currentTimeMillis() - f.lastModified() < maxAgeMs) continue
            try {
                f.parentFile!!.mkdirs()
                val c = URL(url).openConnection() as HttpURLConnection
                c.connectTimeout = 15_000; c.readTimeout = 30_000
                if (c.responseCode != 200) error("HTTP ${c.responseCode}")
                val tmp = File(f.path + ".tmp")
                c.inputStream.use { i -> tmp.outputStream().use { i.copyTo(it) } }
                tmp.renameTo(f) // atomic swap: a failed download keeps the old list
            } catch (e: Exception) {
                errors[url] = e.message ?: e.toString()
            }
        }
        return errors
    }
}
