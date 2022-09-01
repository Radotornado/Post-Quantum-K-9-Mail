package com.fsck.k9.ui.settings.account.postquantum

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.core.widget.doAfterTextChanged
import com.fsck.k9.Preferences.Companion.getPreferences
import com.fsck.k9.activity.MessageList.Companion.launch
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.K9Activity

/**
 * The activity, responsible for the key import. Handles the button presses and warnings.
 * Relies on the PQController.
 */
class PQImportKeysActivity : K9Activity(), View.OnClickListener {

    /**
     * Save the PQController, responsible for the key generation and handling.
     */
    private var controller: PQController? = null

    private var doneBtn: Button? = null
    private var clearBtn: Button? = null
    private var cancelBtn: Button? = null

    private var falseKeyWarning: TextView? = null

    private var publicKeyEditText: TextView? = null
    private var privateKeyEditText: TextView? = null

    /**
     * On creation the layout, title and buttons are created, set and changed if needed.
     */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setLayout(R.layout.import_pq_keys)
        setTitle(R.string.import_pq_keys)

        // fetch accountUuid and initialize controller
        val accountUuid = intent.getStringExtra(EXTRA_ACCOUNT)
        controller = PQController(this, accountUuid)

        // initialize buttons and fields
        initBtn()
    }

    private fun initBtn() {
        doneBtn = findViewById(R.id.done)
        cancelBtn = findViewById(R.id.cancel)
        clearBtn = findViewById(R.id.clearBtn)
        falseKeyWarning = findViewById(R.id.falseKeysWarning)
        publicKeyEditText = findViewById(R.id.pq_public_key)
        privateKeyEditText = findViewById(R.id.pq_private_key)

        doneBtn.let {
            it?.setOnClickListener(this)
        }

        clearBtn?.isEnabled = isThereTextInFields()
        clearBtn?.setOnClickListener {
            publicKeyEditText?.text = ""
            privateKeyEditText?.text = ""
            clearBtn?.isEnabled = false
        }

        publicKeyEditText?.doAfterTextChanged {
            falseKeyWarning?.text = ""
            clearBtn?.isEnabled = true
        }
        privateKeyEditText?.doAfterTextChanged {
            falseKeyWarning?.text = ""
            clearBtn?.isEnabled = true
        }

        cancelBtn?.setOnClickListener {
            finishAsCancelled()
        }
    }

    override fun onClick(v: View) {
        val publicKey = publicKeyEditText?.text.toString()
        val privateKey = privateKeyEditText?.text.toString()

        if (v.id == R.id.done) {
            if (publicKey == "" || privateKey == "") {
                falseKeyWarning?.setTextColor(Color.RED);
                falseKeyWarning?.text = PQConstants.BOTH_KEYS_NEEDED
            } else if (controller?.setNewKeys(publicKey, privateKey) == true) {
                // setNewKeys checks if they are valid
                onNext()
            } else {
                falseKeyWarning?.setTextColor(Color.RED);
                falseKeyWarning?.text = PQConstants.ENTERED_KEYS_NOT_VALID
            }
        }
    }

    private fun isThereTextInFields(): Boolean {
        return !(publicKeyEditText?.text.toString() == "" || privateKeyEditText?.text.toString() == "")
    }

    private fun onNext() {
        getPreferences(applicationContext)
        finishAffinity()
        launch(this)
    }

    fun finishAsCancelled() {
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        private const val EXTRA_ACCOUNT = "account"
        private const val UX_DELAY_MS = 1200L

        fun createIntent(context: Context, accountUuid: String): Intent {
            val intent = Intent(context, PQImportKeysActivity::class.java)
            intent.putExtra(EXTRA_ACCOUNT, accountUuid)
            return intent
        }
    }
}