package snf.app

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

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
    ListPreset("HaGeZi Pro", "Strict · ads, tracking and more", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"),
    ListPreset("OISD Small", "Light · fewest false blocks", "https://small.oisd.nl/"),
)

/** Flips [x] in or out of the set. */
fun <T> Set<T>.toggle(x: T) = if (x in this) this - x else this + x

/** What an app may do. `status` replaces the package name in the app list. */
enum class Access(val title: String, val sub: String?, val status: String?) {
    Allowed("Allowed", null, null),
    Blocked("Blocked", "No network access", "No network access"),
    Bypass("Bypass", "Skips filtering. Restarts the VPN.", "Bypasses Switchyard"),
}

/**
 * All settings live in one SharedPreferences file; [configJson] turns them into the core's config.
 * Reads go through [read], so composables that read a setting recompose when any setting changes.
 */
class Settings private constructor(ctx: Context) {
    companion object {
        @Volatile private var instance: Settings? = null
        /** One per process, so the UI and the service share one prefs listener. */
        fun of(ctx: Context) = instance ?: synchronized(this) { instance ?: Settings(ctx).also { instance = it } }
    }

    private val app = ctx.applicationContext
    private val prefs = app.getSharedPreferences("snf", Context.MODE_PRIVATE)
    private var version by mutableIntStateOf(0)
    // Held strongly: SharedPreferences only keeps a weak reference to its listeners.
    // Every write recomposes readers and pushes the new config into a running engine.
    private val onChange = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        version++
        // The excluded-app list is only read when the tun is built, so that needs a restart.
        if (key == "bypass") FilterVpnService.restart(app) else FilterVpnService.reconfigure(app)
        if (key == "lists" || key == "adblock") FilterVpnService.syncLists(app) // fetch a newly enabled list now, not next hour
    }
    init {
        // Tailscale used to be routeMode "ts", which paused WireGuard and proxy; it's its own switch now.
        if (prefs.getString("routeMode", null) == "ts") prefs.edit().putBoolean("tsOn", true)
            .putString("routeMode", prefs.getString("routeBeforeTs", "off")).remove("routeBeforeTs").apply()
        // An empty pick list used to mean every app; now that's its own switch.
        if (!prefs.contains("routeAll")) prefs.edit { putBoolean("routeAll", prefs.getStringSet("proxied", null).isNullOrEmpty()) }
        prefs.registerOnSharedPreferenceChangeListener(onChange)
    }

    private fun <T> read(f: SharedPreferences.() -> T): T { version; return prefs.f() }
    private fun write(f: SharedPreferences.Editor.() -> Unit) = prefs.edit().apply(f).apply()

    private fun <T> pref(get: SharedPreferences.() -> T, put: SharedPreferences.Editor.(T) -> Unit) =
        object : ReadWriteProperty<Any?, T> {
            override fun getValue(thisRef: Any?, property: KProperty<*>) = read(get)
            override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) = write { put(value) }
        }
    private fun bool(k: String, def: Boolean = false) = pref({ getBoolean(k, def) }, { putBoolean(k, it) })
    private fun str(k: String, def: String = "") = pref({ getString(k, def)!! }, { putString(k, it) })
    private fun strs(k: String) = pref({ getStringSet(k, emptySet())!!.toSet() }, { putStringSet(k, it) })
    // Uids are stored as strings, as they always were.
    private fun uids(k: String) = pref(
        { getStringSet(k, emptySet())!!.mapNotNull { it.toIntOrNull() }.toSet() },
        { putStringSet(k, it.map(Int::toString).toSet()) },
    )

    var dnsUrl by str("dnsUrl", DNS_PRESETS[0].url)
    var dnsBootstrap by str("dnsBootstrap", DNS_PRESETS[0].bootstrap)
    var blockBypass by bool("blockBypass", true)
    var blockedUids by uids("blocked")
    var routedUids by uids("proxied") // apps sent via WireGuard/proxy when routeAll is off
    var routeAll by bool("routeAll", true)
    var bypassPkgs by strs("bypass") // packages kept out of the tun entirely; packages, since that's what Builder takes
    var adblock by bool("adblock")
    var lists by strs("lists")
    var sniSplit by bool("sniSplit")
    var tlsFrag by bool("tlsFrag")
    var hostTricks by bool("hostTricks")
    var blockQuic by bool("blockQuic")
    var proxyUrl by str("proxyUrl")
    var wgActive by str("wgActive")
    var allowDomains by strs("allowDomains")
    var blockDomains by strs("blockDomains")
    var logOn by bool("logOn")
    var skipLan by bool("skipLan", false)
    var tsControlUrl by str("tsControlUrl")
    var tsAuthKey by str("tsAuthKey")
    var tsDns by bool("tsDns")
    var tsOn by bool("tsOn")
    var tsExitNode by str("tsExitNode") // Tailscale IP of the picked exit node

    /** How many traffic-disguise options are on. */
    fun tricksOn() = listOf(sniSplit, tlsFrag, hostTricks, blockQuic).count { it }

    /** True when apps are routed one by one, so each app has its own switch. */
    val pickRoutes get() = routeMode != "off" && !routeAll

    fun access(uid: Int, pkg: String) = when {
        pkg in bypassPkgs -> Access.Bypass
        uid in blockedUids -> Access.Blocked
        else -> Access.Allowed
    }

    /** Blocked and bypass are exclusive: bypassed traffic never reaches us, so it can't be blocked. */
    fun setAccess(uid: Int, pkg: String, a: Access) = write {
        putStringSet("blocked", (if (a == Access.Blocked) blockedUids + uid else blockedUids - uid).map(Int::toString).toSet())
        putStringSet("bypass", if (a == Access.Bypass) bypassPkgs + pkg else bypassPkgs - pkg)
    }

    fun setDns(url: String, bootstrap: String) = write { putString("dnsUrl", url); putString("dnsBootstrap", bootstrap) }

    /** Adds a domain rule; a domain is either allowed or blocked, never both. */
    fun addRule(allow: Boolean, domain: String) = write {
        putStringSet("allowDomains", if (allow) allowDomains + domain else allowDomains - domain)
        putStringSet("blockDomains", if (allow) blockDomains - domain else blockDomains + domain)
    }

    fun removeRule(domain: String) = write {
        putStringSet("allowDomains", allowDomains - domain)
        putStringSet("blockDomains", blockDomains - domain)
    }

    /** "off", "proxy", "wg" or "exit" (a Tailscale exit node, needs tsOn). Falls back to the pre-WireGuard proxyOn switch. */
    var routeMode: String
        get() = read { getString("routeMode", null) ?: if (getBoolean("proxyOn", false)) "proxy" else "off" }
        set(v) = write { putString("routeMode", v) }

    fun wgProfiles(): List<WgProfile> {
        val raw = read { getString("wgProfiles", null) }
            // Pre-profiles installs kept a single config under "wgConf".
            ?: return read { getString("wgConf", "")!! }.takeIf { it.isNotBlank() }?.let { listOf(WgProfile("WireGuard", it)) }.orEmpty()
        val a = JSONArray(raw)
        return List(a.length()) { a.getJSONObject(it).let { o -> WgProfile(o.getString("name"), o.getString("conf")) } }
    }

    fun activeWg() = wgProfiles().let { ps -> ps.firstOrNull { it.name == wgActive } ?: ps.firstOrNull() }

    /** Replaces the profile named [old] (or appends), keeping list order; [activate] also makes it active. */
    fun saveWg(old: String?, p: WgProfile, activate: Boolean) {
        val list = wgProfiles().toMutableList()
        val i = list.indexOfFirst { it.name == old }
        if (i >= 0) list[i] = p else list += p
        writeWg(list) { if (activate) putString("wgActive", p.name) }
    }

    fun deleteWg(name: String) = writeWg(wgProfiles().filter { it.name != name })

    // Also drops the pre-profiles "wgConf" copy, so deleting a profile really removes its key.
    private fun writeWg(list: List<WgProfile>, more: SharedPreferences.Editor.() -> Unit = {}) = write {
        putString("wgProfiles", JSONArray(list.map { JSONObject().put("name", it.name).put("conf", it.conf) }).toString())
        remove("wgConf")
        more()
    }

    fun listFile(url: String) = File(app.filesDir, "lists/%08x.txt".format(url.hashCode()))

    fun configJson(): String = JSONObject().apply {
        put("dnsUpstream", dnsUrl)
        put("dnsBootstrap", JSONArray(dnsBootstrap.split(',').map { it.trim() }.filter { it.isNotEmpty() }))
        put("blockedUids", JSONArray(blockedUids.toList()))
        put("blocklists", JSONArray(if (adblock) lists.map { listFile(it).path }.filter { File(it).exists() } else emptyList()))
        put("blockBypass", blockBypass)
        put("sniSplit", sniSplit)
        put("tlsFrag", tlsFrag)
        put("hostTricks", hostTricks)
        put("blockQuic", blockQuic)
        put("proxyUrl", if (routeMode == "proxy") proxyUrl else "")
        put("wgConf", if (routeMode == "wg") activeWg()?.conf.orEmpty() else "")
        put("routeAll", routeAll)
        put("routeUids", JSONArray(routedUids.toList()))
        put("allowDomains", JSONArray(allowDomains.toList()))
        put("blockDomains", JSONArray(blockDomains.toList()))
        put("log", logOn)
        put("tsDir", if (tsOn) File(app.filesDir, "tailscale").path else "")
        // Like Tailscale's app: the name set in Android's About phone, else the model; control turns it into a DNS label.
        put("tsHostname", android.provider.Settings.Global.getString(app.contentResolver, android.provider.Settings.Global.DEVICE_NAME) ?: android.os.Build.MODEL)
        put("tsControlUrl", tsControlUrl)
        put("tsAuthKey", tsAuthKey)
        put("tsDns", tsOn && tsDns)
        val exit = tsOn && routeMode == "exit"
        put("tsExit", exit)
        put("tsExitNode", if (exit) tsExitNode else "")
    }.toString()

    /**
     * Downloads lists that are missing or a day old (all of them if [force]). Returns per-URL errors.
     * Blocking; call via [FilterVpnService.syncLists]. A download writes "listsAt", so the prefs
     * listener refreshes the UI and the engine like any other setting.
     */
    fun refreshLists(force: Boolean = false): Map<String, String> {
        var downloaded = false
        val errors = mutableMapOf<String, String>()
        for (url in lists) {
            val f = listFile(url)
            if (!force && f.exists() && System.currentTimeMillis() - f.lastModified() < 24 * 3600_000L) continue
            try {
                f.parentFile!!.mkdirs()
                val c = URL(url).openConnection() as HttpURLConnection
                c.connectTimeout = 15_000; c.readTimeout = 30_000
                if (c.responseCode != 200) error("HTTP ${c.responseCode}")
                val tmp = File(f.path + ".tmp")
                c.inputStream.use { i -> tmp.outputStream().use { i.copyTo(it) } }
                tmp.renameTo(f) // atomic swap: a failed download keeps the old list
                downloaded = true
            } catch (e: Exception) {
                errors[url] = e.message ?: e.toString()
            }
        }
        if (downloaded) write { putLong("listsAt", System.currentTimeMillis()) }
        return errors
    }
}
