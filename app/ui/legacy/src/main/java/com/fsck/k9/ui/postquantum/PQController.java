package com.fsck.k9.ui.postquantum;


import java.util.Base64;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;
import com.example.liboqs.Signature;
import com.fsck.k9.Account;
import com.fsck.k9.mail.internet.MimeUtility;

import static com.fsck.k9.Preferences.getPreferences;


/**
 * PQController is here, because of circular dependencies.
 * TODO try to move it somewhere more sensible
 * TODO expand comment
 */
public class PQController {

    private final Account account;
    private final Context context;
    private Signature signature;

    public PQController(final Context context, final String uuid) {
        this.context = context;
        this.account = getPreferences(context).getAccount(uuid);
        if (account != null) {
            String publicKeyStr = MimeUtility.unfold(account.getPqPublicKey());
            String privateKeyStr = MimeUtility.unfold(account.getPqPrivateKey());
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                byte[] publicKey = Base64.getDecoder().decode(publicKeyStr);
                byte[] privateKey = Base64.getDecoder().decode(privateKeyStr);
                this.signature = new Signature(account.getPqAlgorithm(), privateKey, publicKey);
                System.out.println();
            }
        }
    }

    public Boolean checkIfAlgorithmChosen() {
        return account.getPqAlgorithm() == null;
    }

    public String getUuid() {
        return account.getUuid();
    }

    public Boolean checkIfKeysAlreadyGenerated() {
        return account.getPqKeysetExists();
    }

    public void generateKeys() {
        signature = new Signature(account.getPqAlgorithm());
        signature.generate_keypair();
        account.setPqPublicKey(getPublicKeyStr());
        account.setPqPrivateKey(getPrivateKeyStr());
        account.setPqKeysetExists(true);
        getPreferences(context).saveAccount(account);
    }

    public byte[] getPublicKey() {
        return signature.export_public_key();
    }

    @SuppressLint("NewApi")
    public String getPublicKeyStr() {
        return Base64.getMimeEncoder().encodeToString(signature.export_public_key());
    }

    @SuppressLint("NewApi")
    public String getPrivateKeyStr() {
        return Base64.getMimeEncoder().encodeToString(signature.export_secret_key());
    }

    public byte[] getPrivateKey() {
        return signature.export_secret_key();
    }

}
