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
 * The activity, responsible for the key generation. Handles the button presses and warnings.
 * Relies on the PQController.
 */
class PQGenerateKeysActivity : K9Activity() {

    /**
     * Save the PQController, resposible for the key generation and handling.
     */
    private var controller: PQController? = null

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
        val exportKeys = findViewById<Button>(R.id.downloadKeys)
        val verifyKeys = findViewById<Button>(R.id.verifyKeys)

        if (controller?.checkIfKeysAlreadyGenerated() == false) {
            noKeysWarning.text = Constants.NO_SAVED_KEYS_WARNING;
        } else {
            noKeysWarning.text = Constants.KEYS_ALREADY_GENERATED_WARNING;
            generateKeysBtn.text = Constants.GENERATE_NEW_KEYS_BTN
            publicKey.text = Constants.CURRENT_PUBLIC_KEY + controller!!.publicKeyStr
        }

        exportKeys.isEnabled = controller!!.checkIfKeysAlreadyGenerated()
        verifyKeys.isEnabled = controller!!.checkIfKeysAlreadyGenerated()

        generateKeysBtn.setOnClickListener {
            if (controller?.checkIfAlgorithmChosen() == true) {
                // TODO add delay if needed
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
            var publicKey = controller!!.publicKey
            // TODO
        }

        verifyKeys.setOnClickListener {
            if(controller!!.verifyKeys()) {
                // TODO change text color
                noKeysWarning.text = Constants.KEYS_VALID
            } else {
                noKeysWarning.text = Constants.KEYS_NOT_VALID
            }
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
}
