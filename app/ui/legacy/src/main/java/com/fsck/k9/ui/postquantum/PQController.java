package com.fsck.k9.ui.postquantum;


import java.util.Base64;
import java.util.Objects;

import android.annotation.SuppressLint;
import android.content.Context;

import com.example.liboqs.Signature;
import com.fsck.k9.Account;
import com.fsck.k9.mail.internet.MimeUtility;

import static com.fsck.k9.Preferences.getPreferences;


/**
 * PQController is the ui package (for now), because of circular dependencies. Used by the PQGenerateKeysActivity, it
 * fetches the signature algorithm from the Account by the uuid and context and handles key generation and export.
 */
public class PQController {

    private static final String PUBLIC_KEY_HEADER = "------ BEGIN POST QUANTUM PUBLIC KEY FOR ";
    private static final String PUBLIC_KEY_FOOTER = "------ END POST QUANTUM PUBLIC KEY FOR ";
    private static final String PRIVATE_KEY_HEADER = "------ BEGIN POST QUANTUM PRIVATE KEY FOR ";
    private static final String PRIVATE_KEY_FOOTER = "------ END POST QUANTUM PRIVATE KEY FOR ";
    private static final String END = " ------\n";

    /**
     * The properties saved in the controller are the account (needed for saving PQ fields), context (needed for saving
     * the account changes) and signature (needed for PQ operations).
     */
    private final Account account;
    private final Context context;
    private Signature signature;

    /**
     * When instantiating the controller, using the context and uuid a new Signature is created.
     *
     * @param context The context is needed in order to fetch the account.
     * @param uuid    The uuid is needed in order to fetch the correct account.
     */
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
            }
        }
    }

    /**
     * Checks if an algorithm has been chosen (as DILITHIUM is the default this should always result in true).
     *
     * @return {@code true} if an algorithm has been chosen and {@code false} if none is chosen
     */
    public Boolean checkIfAlgorithmChosen() {
        return account.getPqAlgorithm() != null;
    }

    /**
     * Checks if there are existent PQ keys for this account.
     *
     * @return {@code true} if PQ keys exist, {@code false} if not
     */
    public Boolean checkIfKeysAlreadyGenerated() {
        return account.getPqKeysetExists();
    }

    /**
     * Generates keys for this account, using the selected algorithm. Then the account changes are saved through the
     * preferences.
     */
    public void generateKeys() {
        signature = new Signature(account.getPqAlgorithm());
        signature.generate_keypair();
        account.setPqPublicKey(getPublicKeyStr());
        account.setPqPrivateKey(getPrivateKeyStr());
        account.setPqKeysetExists(true);
        getPreferences(context).saveAccount(account);
    }

    /**
     * Returns the public key as a byte array.
     *
     * @return The public key
     */
    public byte[] getPublicKey() {
        return signature.export_public_key();
    }

    /**
     * Returns the private key as a byte array.
     *
     * @return The private key
     */
    public byte[] getPrivateKey() {
        return signature.export_secret_key();
    }

    /**
     * Returns the public key, exported as a String.
     *
     * @return the public key as a String
     */
    @SuppressLint("NewApi")
    public String getPublicKeyStr() {
        return Base64.getMimeEncoder().encodeToString(signature.export_public_key());
    }

    /**
     * Returns the private key, exported as a String.
     *
     * @return the private key as a String
     */
    @SuppressLint("NewApi")
    public String getPrivateKeyStr() {
        return Base64.getMimeEncoder().encodeToString(signature.export_secret_key());
    }

    /**
     * Verifying the keys happens through singing and verifying the signature.
     * False keys can happen when the user has generated keys and then changed the algorithm (this is a known bug).
     *
     * @return {@code true} if both keys are valid, {@code false} if not
     */
    public boolean verifyKeys() {
        try {
            byte[] textToVerify = "verify".getBytes();
            byte[] sign = signature.sign(textToVerify);
            return signature.verify(textToVerify, sign, getPublicKey());
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * TODO
     * @return
     */
    public String exportPublicKey() {
        StringBuilder output = new StringBuilder();
        output.append(PUBLIC_KEY_HEADER + Objects.requireNonNull(account.getPqAlgorithm()).toUpperCase() + END);
        output.append(account.getPqPublicKey() + "\n");
        output.append(PUBLIC_KEY_FOOTER + Objects.requireNonNull(account.getPqAlgorithm()).toUpperCase() + END);
        return output.toString();
    }

    /**
     * TODO
     * @return
     */
    public String exportPrivateKey() {
        StringBuilder output = new StringBuilder();
        output.append(PRIVATE_KEY_HEADER + Objects.requireNonNull(account.getPqAlgorithm()).toUpperCase() + END);
        output.append(account.getPqPrivateKey() + "\n");
        output.append(PRIVATE_KEY_FOOTER + Objects.requireNonNull(account.getPqAlgorithm()).toUpperCase() + END);
        return output.toString();
    }
}
