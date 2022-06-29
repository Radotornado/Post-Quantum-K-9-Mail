package com.fsck.k9.ui.postquantum

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import com.fsck.k9.Preferences.Companion.getPreferences
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.K9Activity

/**
 * TODO explain class
 */
class PQGenerateKeysActivity : K9Activity() {

    private var controller: PQController? = null

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

        val generateKeysBtn = findViewById<Button>(R.id.generateKeysButton)
        val exportPublicKeyBtn = findViewById<Button>(R.id.downloadPublicKeyButton)
        val exportPrivateKeyBtn = findViewById<Button>(R.id.downloadPrivateKeyButton)

        if (controller?.checkIfKeysAlreadyGenerated() == false) {
            noKeysWarning.text = Constants.NO_SAVED_KEYS_WARNING;
        } else {
            noKeysWarning.text = Constants.KEYS_ALREADY_GENERATED_WARNING;
            generateKeysBtn.text = Constants.GENERATE_NEW_KEYS_BTN
        }

        exportPublicKeyBtn.isEnabled = controller!!.checkIfKeysAlreadyGenerated()
        exportPrivateKeyBtn.isEnabled = controller!!.checkIfKeysAlreadyGenerated()

        generateKeysBtn.setOnClickListener {
            if (controller?.checkIfAlgorithmChosen() != true) {
                // TODO add delay if needed
                controller!!.generateKeys()
                noKeysWarning.text = Constants.KEYS_ALREADY_GENERATED_WARNING
                exportPublicKeyBtn.isEnabled = true
                exportPrivateKeyBtn.isEnabled = true
                generateKeysBtn.text = Constants.GENERATE_NEW_KEYS_BTN
                generateKeysBtn.isEnabled = true
            }
        }

        exportPublicKeyBtn.setOnClickListener {
            var publicKey = controller!!.publicKey
        }

        exportPrivateKeyBtn.setOnClickListener {
            var privateKey = controller!!.privateKey
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
    const val NO_SAVED_KEYS_WARNING = "It appears that you have no saved keys in your account. Please generate a pair."
    const val KEYS_ALREADY_GENERATED_WARNING = "You have generated a pair of keys. You are able to create a new one, but it is not advised."
    const val GENERATE_NEW_KEYS_BTN = "Generate new set of keys"
}
