package com.fsck.k9.ui.postquantum

import android.Manifest.permission.READ_EXTERNAL_STORAGE
import android.Manifest.permission.WRITE_EXTERNAL_STORAGE
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
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
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.K9Activity
import java.io.OutputStream

/**
 * The activity, responsible for the key generation. Handles the button presses and warnings.
 * Relies on the PQController.
 */
class PQGenerateKeysActivity : K9Activity() {

    /**
     * Save the PQController, resposible for the key generation and handling.
     */
    private var controller: PQController? = null


    lateinit var notificationManager: NotificationManager
    lateinit var notificationChannel: NotificationChannel
    lateinit var builder: Notification.Builder
    private val channelId = "i.apps.notifications"
    private val description = "Test notification"


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

        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // initialize buttons
        handleButtons()
    }

    private fun handleButtons() {
        val noKeysWarning: TextView = findViewById<View>(R.id.keyGenerationWarning) as TextView
        val publicKey: TextView = findViewById<View>(R.id.publicKey) as TextView

        val generateKeysBtn = findViewById<Button>(R.id.generateKeysButton)
        val exportKeys = findViewById<Button>(R.id.downloadKeys)
        val verifyKeys = findViewById<Button>(R.id.verifyKeys)

        if (controller?.checkIfKeysAlreadyGenerated() == false) {
            noKeysWarning.setTextColor(Color.YELLOW);
            noKeysWarning.text = Constants.NO_SAVED_KEYS_WARNING;
        } else {
            noKeysWarning.setTextColor(Color.rgb(0,130,0));
            noKeysWarning.text = Constants.KEYS_ALREADY_GENERATED_WARNING;
            generateKeysBtn.text = Constants.GENERATE_NEW_KEYS_BTN
            publicKey.text = Constants.CURRENT_PUBLIC_KEY + controller!!.publicKeyStr
        }

        exportKeys.isEnabled = controller!!.checkIfKeysAlreadyGenerated()
        verifyKeys.isEnabled = controller!!.checkIfKeysAlreadyGenerated()

        generateKeysBtn.setOnClickListener {
            if (controller?.checkIfAlgorithmChosen() == true) {
                controller!!.generateKeys()
                noKeysWarning.text = Constants.KEYS_ALREADY_GENERATED_WARNING
                exportKeys.isEnabled = true
                verifyKeys.isEnabled = true
                generateKeysBtn.text = Constants.GENERATE_NEW_KEYS_BTN
                generateKeysBtn.isEnabled = true
                publicKey.text = Constants.CURRENT_PUBLIC_KEY + controller!!.publicKeyStr
            }
        }

        exportKeys.setOnClickListener {
            exportKeys()
        }

        verifyKeys.setOnClickListener {
            if(controller!!.verifyKeys()) {
                // TODO change text color
                noKeysWarning.setTextColor(Color.rgb(0,130,0));
                noKeysWarning.text = Constants.KEYS_VALID
            } else {
                noKeysWarning.setTextColor(Color.RED);
                noKeysWarning.text = Constants.KEYS_NOT_VALID
            }
        }
    }

    private fun exportKeys() {
        requestPermissions(arrayOf(WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE), 1)
        val pub = saveFileKey("PQK9_public_key.txt", "PQK9 Public Key", controller!!.exportPublicKey())
        val priv = saveFileKey("PQK9_private_key.txt", "PQK9 Private Key", controller!!.exportPrivateKey())

        val textView: TextView = findViewById<View>(R.id.keyGenerationWarning) as TextView
        if (pub && priv) {
            textView.setTextColor(Color.rgb(0,130,0));
            textView.text = Constants.KEYS_EXPORTED
        } else {
            textView.setTextColor(Color.RED);
            textView.text = Constants.KEYS_EXPORT_FAILED
        }
    }

    private fun saveFileKey(fileName:String, fileTitle:String, keyToWrite:String): Boolean {
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

object Constants {
    const val NO_SAVED_KEYS_WARNING = "It appears that you have no saved keys in your account. Please generate a pair. After pressing the button please wait, until the new key is shown to the screen."
    const val KEYS_ALREADY_GENERATED_WARNING = "You have generated a pair of keys. You are able to create a new one, but it is not advised. After pressing the button please wait, until the new key is shown to the screen."
    const val GENERATE_NEW_KEYS_BTN = "Generate new set of keys"
    const val CURRENT_PUBLIC_KEY = "Current public key: "
    const val KEYS_VALID = "The current keys are valid."
    const val KEYS_NOT_VALID = "The current keys are NOT valid. Please generate new keys after algorithm change."
    const val KEYS_EXPORTED = "Keys have been exported successfully. \nYou can find them in two separate files, called \"PQK9_public_key.txt\" and \"PQK9_public_key.txt\" in your \"Documents\" folder."
    const val KEYS_EXPORT_FAILED = "Keys export failed."
}
