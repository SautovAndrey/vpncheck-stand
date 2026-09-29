package ru.vpncheck.agent

import android.util.AtomicFile
import org.json.JSONArray
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

object JsonStore {
    fun read(file: File): JSONArray = try {
        JSONArray(String(AtomicFile(file).readFully(), Charsets.UTF_8))
    } catch (_: FileNotFoundException) {
        JSONArray()
    }

    fun write(file: File, items: JSONArray) {
        val atomic = AtomicFile(file)
        if (items.length() == 0) {
            atomic.delete()
            return
        }
        val stream = atomic.startWrite()
        try {
            stream.write(items.toString().toByteArray(Charsets.UTF_8))
            atomic.finishWrite(stream)
        } catch (e: IOException) {
            atomic.failWrite(stream)
            throw e
        }
    }
}
