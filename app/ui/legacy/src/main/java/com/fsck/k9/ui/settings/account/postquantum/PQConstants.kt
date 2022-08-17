package com.fsck.k9.ui.settings.account.postquantum

object PQConstants {
    const val PUBLIC_KEY_FILE_NAME = "PQK9_public_key.txt"
    const val PRIVATE_KEY_FILE_NAME = "PQK9_private_key.txt"
    const val PUBLIC_KEY_FILE_TITLE = "PQK9 Public Key"
    const val PRIVATE_KEY_FILE_TITLE = "PQK9 Private Key"
    const val NO_SAVED_KEYS_WARNING = "It appears that you have no saved keys in your account. Please generate a pair. After pressing the button please wait, until the new key is shown to the screen."
    const val KEYS_ALREADY_GENERATED_WARNING = "You have already generated a pair of keys. \n\nYou are able to create a new one, but it is not advised. \n\nAfter pressing the button please wait, until the new key is shown above."
    const val GENERATE_NEW_KEYS_BTN = "Generate new set of keys"
    const val CURRENT_PUBLIC_KEY = "Current public key: "
    const val KEYS_VALID = "The current keys are valid."
    const val KEYS_NOT_VALID = "The current keys are NOT valid. Please generate new keys after algorithm change."
    const val KEYS_EXPORTED = "Keys have been exported successfully. \n\nYou can find them in two separate files, called \"PQK9_public_key.txt\" and \"PQK9_public_key.txt\" in your \"Documents\" folder.\n\nKeep in mind that you should not share your private key with anyone."
    const val KEYS_EXPORT_FAILED = "Keys export failed."
    const val ENTERED_KEYS_NOT_VALID = "The keys that were entered by you appear not to be valid. Please follow the instructions above."
    const val BOTH_KEYS_NEEDED = "You need to enter both keys."
}