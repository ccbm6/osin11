package com.personal.recon

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

data class Scan(val id: Long, val type: String, val target: String, val lines: List<String>)

/** تخزين مشفّر: المفاتيح في EncryptedSharedPreferences والسجل في EncryptedFile (AES-256) */
class Store(private val ctx: Context) {
    private val master = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "secure", master,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    private val histFile get() = File(ctx.filesDir, "history.enc")

    private fun enc(f: File) = EncryptedFile.Builder(
        ctx, f, master, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
    ).build()

    fun key(name: String): String = prefs.getString(name, "") ?: ""
    fun setKey(name: String, value: String) { prefs.edit().putString(name, value).apply() }

    fun load(): List<Scan> {
        val f = histFile
        if (!f.exists()) return emptyList()
        return try {
            val text = enc(f).openFileInput().use { String(it.readBytes(), Charsets.UTF_8) }
            val arr = JSONArray(text)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val l = o.getJSONArray("lines")
                Scan(o.getLong("id"), o.getString("type"), o.getString("target"),
                    (0 until l.length()).map { l.getString(it) })
            }
        } catch (e: Exception) { emptyList() }
    }

    @Synchronized
    fun save(list: List<Scan>) {
        val arr = JSONArray()
        list.forEach { s ->
            arr.put(JSONObject().put("id", s.id).put("type", s.type)
                .put("target", s.target).put("lines", JSONArray(s.lines)))
        }
        val f = histFile
        f.delete() // EncryptedFile لا تكتب فوق ملف موجود
        enc(f).openFileOutput().use { it.write(arr.toString().toByteArray(Charsets.UTF_8)) }
    }
}
