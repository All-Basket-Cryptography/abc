package org.allbasket.abc.android.consumer

import android.app.Activity
import android.os.Bundle
import android.util.Log
import org.allbasket.abc.android.Sha256

class ProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val input = byteArrayOf(0x61, 0x62, 0x63)
        val expected = byteArrayOf(
            -70, 120, 22, -65, -113, 1, -49, -22, 65, 65, 64, -34, 93, -82, 34, 35,
            -80, 3, 97, -93, -106, 23, 122, -100, -76, 16, -1, 97, -14, 0, 21, -83,
        )
        check(Sha256.implementation() == "sha256-abc-rust-portable")
        check(Sha256.digest(input).contentEquals(expected))
        val stream = Sha256()
        stream.use {
            it.update(byteArrayOf(0x61))
            it.update(byteArrayOf(0x62, 0x63))
            check(it.finish().contentEquals(expected))
            check(runCatching { it.finish() }.exceptionOrNull() is IllegalStateException)
            it.reset()
            it.update(input)
            check(it.finish().contentEquals(expected))
        }
        check(runCatching { stream.update(input) }.exceptionOrNull() is IllegalStateException)
        stream.close()
        Log.i("ABC-SDK", "SHA-256 AAR consumer passed")
        finish()
    }
}
