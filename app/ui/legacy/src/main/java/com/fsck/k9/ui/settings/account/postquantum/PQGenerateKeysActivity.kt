package com.fsck.k9.ui.settings.account.postquantum

import android.Manifest.permission.READ_EXTERNAL_STORAGE
import android.Manifest.permission.WRITE_EXTERNAL_STORAGE
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.view.View
import android.widget.Button
import android.widget.TextView
import com.fsck.k9.mail.internet.MimeUtility
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.K9Activity
import java.io.OutputStream

/**
 * The activity, responsible for the key generation. Handles the button presses and warnings.
 * Relies on the PQController.
 */
class PQGenerateKeysActivity : K9Activity() {

    /**
     * Save the PQController, responsible for the key generation and handling.
     */
    private var controller: PQController? = null

    private var backBtn: Button? = null
    private var verifyBtn: Button? = null

    /**
     * On creation the layout, title and buttons are created, set and changed if needed.
     */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setLayout(R.layout.generate_pq_keys)
        setTitle(R.string.generate_pq_keys)

        // fetch accountUuid and initialize controller
        val accountUuid = intent.getStringExtra(EXTRA_ACCOUNT)
        controller = PQController(this, accountUuid)

        // initialize buttons
        handleButtons()
    }

    private fun handleButtons() {
        val noKeysWarning: TextView = findViewById<View>(R.id.keyGenerationWarning) as TextView
        val publicKey: TextView = findViewById<View>(R.id.publicKey) as TextView

        val generateKeysBtn = findViewById<Button>(R.id.generateKeysButton)
        val exportKeys = findViewById<Button>(R.id.exportButton)

        backBtn = findViewById(R.id.back)
        verifyBtn = findViewById(R.id.verify)

        if (controller?.checkIfKeysAlreadyGenerated() == false) {
            noKeysWarning.setTextColor(Color.YELLOW);
            noKeysWarning.text = PQConstants.NO_SAVED_KEYS_WARNING;
        } else {
            noKeysWarning.setTextColor(Color.rgb(0, 140, 0));
            noKeysWarning.text = PQConstants.KEYS_ALREADY_GENERATED_WARNING;
            generateKeysBtn.text = PQConstants.GENERATE_NEW_KEYS_BTN
            val test = controller!!.publicKeyStr
            publicKey.text = PQConstants.CURRENT_PUBLIC_KEY + MimeUtility.unfold(controller!!.publicKeyStr)
        }

        exportKeys.isEnabled = controller!!.checkIfKeysAlreadyGenerated()

        generateKeysBtn.setOnClickListener {
            if (controller?.checkIfAlgorithmChosen() == true) {
                controller!!.generateKeys()
                noKeysWarning.text = PQConstants.KEYS_ALREADY_GENERATED_WARNING
                exportKeys.isEnabled = true
                generateKeysBtn.text = PQConstants.GENERATE_NEW_KEYS_BTN
                generateKeysBtn.isEnabled = true
                publicKey.text = PQConstants.CURRENT_PUBLIC_KEY + controller!!.publicKeyStr
            }
        }

        exportKeys.setOnClickListener {
            exportKeys()
        }

        backBtn?.setOnClickListener {
            finishAsCancelled()
        }

        verifyBtn?.setOnClickListener {
            if (controller!!.verifyKeys()) {
                noKeysWarning.setTextColor(Color.rgb(0, 130, 0));
                noKeysWarning.text = PQConstants.KEYS_VALID
            } else {
                noKeysWarning.setTextColor(Color.RED);
                noKeysWarning.text = PQConstants.KEYS_NOT_VALID
            }
        }
    }

    private fun exportKeys() {
        requestPermissions(arrayOf(WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE), 1)
        val pub = saveFileKey(
            PQConstants.PUBLIC_KEY_FILE_NAME,
            PQConstants.PUBLIC_KEY_FILE_TITLE,
            controller!!.exportPublicKey()
        )
        val priv = saveFileKey(
            PQConstants.PRIVATE_KEY_FILE_NAME,
            PQConstants.PRIVATE_KEY_FILE_TITLE,
            controller!!.exportPrivateKey()
        )

        val textView: TextView = findViewById<View>(R.id.keyGenerationWarning) as TextView
        if (pub && priv) {
            textView.setTextColor(Color.rgb(0, 130, 0));
            textView.text = PQConstants.KEYS_EXPORTED
        } else {
            textView.setTextColor(Color.RED);
            textView.text = PQConstants.KEYS_EXPORT_FAILED
        }
    }

    private fun saveFileKey(fileName: String, fileTitle: String, keyToWrite: String): Boolean {
        val externalUri: Uri = MediaStore.Files.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val relativeLocation: String = Environment.DIRECTORY_DOCUMENTS
        val contentValues = ContentValues()
        contentValues.put(MediaStore.Files.FileColumns.DISPLAY_NAME, fileName)
        contentValues.put(MediaStore.Files.FileColumns.MIME_TYPE, "application/text")
        contentValues.put(MediaStore.Files.FileColumns.TITLE, fileTitle)
        contentValues.put(MediaStore.Files.FileColumns.DATE_ADDED, System.currentTimeMillis() / 1000)
        contentValues.put(MediaStore.Files.FileColumns.RELATIVE_PATH, relativeLocation)
        contentValues.put(MediaStore.Files.FileColumns.DATE_TAKEN, System.currentTimeMillis())

        val fileUri: Uri? = contentResolver.insert(externalUri, contentValues)
        return try {
            val outputStream: OutputStream? = fileUri?.let { it1 -> contentResolver.openOutputStream(it1) }
            outputStream?.write(keyToWrite.toByteArray())
            outputStream?.close()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun finishAsCancelled() {
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        private const val EXTRA_ACCOUNT = "account"
        private const val UX_DELAY_MS = 1200L

        fun createIntent(context: Context, accountUuid: String): Intent {
            val intent = Intent(context, PQGenerateKeysActivity::class.java)
            intent.putExtra(EXTRA_ACCOUNT, accountUuid)
            return intent
        }
    }
}
