package com.quantumaes.citadelpqvpn

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * N-3: копирование чувствительного (ссылка абонента, `client_id`) в системный буфер обмена.
 *
 * Обычный `Clipboard.setData` из Dart делает ровно одно — кладёт текст. Здесь добавлены две вещи,
 * которых у него нет:
 *
 *  * **пометка «чувствительное»** (`ClipDescription.EXTRA_IS_SENSITIVE`, Android 13+): системная
 *    плашка-превью буфера показывает «•••» вместо содержимого. Без неё выданная ссылка (а вместе с
 *    ней и адрес сервера) выводится на весь экран в момент копирования — при том, что копируют её
 *    обычно как раз при посторонних;
 *  * **автоочистка** через заданный срок: ссылка не должна жить в буфере до перезагрузки. Чистим с
 *    Handler'а процесса, а не Dart-таймером: изолят UI умирает вместе с окном, процесс — нет.
 *
 * **Граница, о которой честно:** с Android 10 система запрещает менять буфер приложению без фокуса.
 * Если к моменту очистки приложение в фоне, `setPrimaryClip` молча ничего не сделает — поэтому
 * чистка ещё раз пробуется при возвращении приложения на экран ([onResume]). Гарантией это не
 * является ни в каком виде; гарантия здесь одна — не показывать секрет в превью.
 */
object SensitiveClipboard {
    private val handler = Handler(Looper.getMainLooper())

    /** Что мы положили в буфер последним: чистим ТОЛЬКО это, чужое (скопированное человеком
     *  после нас) не трогаем. */
    @Volatile
    private var pending: String? = null

    private var scheduled: Runnable? = null

    /** Скопировать [text] с пометкой «чувствительное» и очисткой через [ttlSeconds]. */
    fun copy(ctx: Context, text: String, ttlSeconds: Int): Boolean {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
        val clip = ClipData.newPlainText("", text)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        return try {
            cm.setPrimaryClip(clip)
            pending = text
            scheduled?.let { handler.removeCallbacks(it) }
            val task = Runnable { clearIfOurs(ctx) }
            scheduled = task
            handler.postDelayed(task, ttlSeconds * 1000L)
            true
        } catch (e: Exception) {
            android.util.Log.w("CitadelClip", "буфер обмена недоступен: ${e.message}")
            false
        }
    }

    /** Приложение вернулось на экран — доочистить то, что не удалось стереть из фона (Android 10+). */
    fun onResume(ctx: Context) {
        if (pending == null) return
        clearIfOurs(ctx)
    }

    /**
     * Стереть буфер, если в нём всё ещё лежит НАШ текст. Сравнение обязательно: между копированием
     * и очисткой человек мог скопировать что-то своё, и затирать это — сломанное поведение, за
     * которое приложение выключают, а не хвалят.
     */
    private fun clearIfOurs(ctx: Context) {
        val want = pending ?: return
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        try {
            // Чтение буфера без фокуса на Android 10+ возвращает null — тогда просто ждём
            // следующей попытки (onResume): «не смогли прочитать» ≠ «там уже чужое».
            val current = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
                ?: return
            if (current != want) {
                pending = null // человек скопировал своё — наша ответственность кончилась
                return
            }
            if (Build.VERSION.SDK_INT >= 28) {
                cm.clearPrimaryClip()
            } else {
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
            pending = null
        } catch (e: Exception) {
            android.util.Log.w("CitadelClip", "не очистить буфер: ${e.message}")
        }
    }
}
