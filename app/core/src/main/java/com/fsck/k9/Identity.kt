package com.fsck.k9

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class Identity(
    val description: String? = null,
    val name: String? = null,
    val email: String? = null,
    val signature: String? = null,
    val signatureUse: Boolean = false,
    val replyTo: String? = null,
    var isPQSignOnly: Boolean? = false
) : Parcelable {
    // TODO remove when callers are converted to Kotlin
    fun withName(name: String?) = copy(name = name)
    fun withSignature(signature: String?) = copy(signature = signature)
    fun withSignatureUse(signatureUse: Boolean) = copy(signatureUse = signatureUse)
    fun withEmail(email: String?) = copy(email = email)
}
