package de.uni_passau.fim.pqsigningapp;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.example.liboqs.Rand;
import com.example.liboqs.Signature;
import com.example.liboqs.Sigs;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class MainActivity extends AppCompatActivity {

    /**
     * Save all algorithms, the chosen one, the signed message and public key.
     */
    private String[] algorithms;
    private Signature signature;
    private byte[] signedMessage;
    private byte[] publicKey;

    private EditText plainTextToSign;
    private boolean isPublicKeyShown;
    private boolean isSignedMessageModified;

    /**
     * Initialize the app. This includes fetching all available algorithms, view and
     * button listeners.
     */
    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle("Sign and validate example");
        isPublicKeyShown = false;
        isSignedMessageModified = false;

        algorithms = getAllWantedAlgs();
        initView();
        initButtons();
    }

    /**
     * Fetches all available algorithms, filtered so only the three finalists are retrieved.
     *
     * @return The wanted algorithms.
     */
    @RequiresApi(api = Build.VERSION_CODES.N) // not so important for now
    private String[] getAllWantedAlgs() {
        List<String> algs = Sigs.get_enabled_sigs();
        algs = algs.stream()
                .filter(e -> e.toLowerCase().contains("dilithium")
                        || e.toLowerCase().contains("rainbow")
                        || e.toLowerCase().contains("falcon"))
                .collect(Collectors.toList());
        return algs.toArray(new String[0]);
    }

    /**
     * Initializes the dropdown with the algorithms and creates a listener for it.
     */
    private void initView() {
        Spinner dropdown = findViewById(R.id.supportedAlgorithms);

        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, algorithms);
        dropdown.setAdapter(adapter);
        dropdown.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                selectSigner(i);
            }

            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
    }

    /**
     * Selects the chosen algorithm, creates the signature and public key.
     * Then the information is set and the text is signed.
     *
     * @param chosenAlgorithmIndex The index from the dropdown.
     */
    private void selectSigner(final int chosenAlgorithmIndex) {
        String chosenAlgorithm = algorithms[chosenAlgorithmIndex];
        signature = new Signature(chosenAlgorithm);
        publicKey = signature.generate_keypair();
        setTextViews(signature.get_details());
        handleTextToSign();
        setPublicKey();
    }

    /**
     * Sets the information about the chosen algorithm.
     *
     * @param algorithm The chosen algorithm.
     */
    @SuppressLint("SetTextI18n")
    private void setTextViews(final List<String> algorithm) {
        TextView algorithmName = findViewById(R.id.algorithmName);
        TextView algorithmVersion = findViewById(R.id.algorithmVersion);
        TextView nistLevel = findViewById(R.id.nistLevel);
        TextView indCCA = findViewById(R.id.indCCA);
        TextView publicKey = findViewById(R.id.publicKey);
        TextView privateKey = findViewById(R.id.privateKey);
        TextView lengthSignature = findViewById(R.id.lengthSignature);

        algorithmName.setText("Chosen algorithm: " + algorithm.get(0));
        algorithmVersion.setText("Version: " + algorithm.get(1));
        nistLevel.setText("NIST level: " + algorithm.get(2));
        indCCA.setText("Is EUF-CMA: " + algorithm.get(3));
        publicKey.setText("Length public key (bytes): " + algorithm.get(4));
        privateKey.setText("Length private key (bytes): " + algorithm.get(5));
        lengthSignature.setText("Maximum length signature (bytes): " + algorithm.get(6));
    }

    /**
     * Call the plain text to be signed, by attaching a listener.
     */
    private void handleTextToSign() {
        plainTextToSign = findViewById(R.id.document);
        if (!plainTextToSign.getText().toString().equals("")) {
            sign();
        }
        plainTextToSign.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void afterTextChanged(Editable editable) {
                sign();
            }
        });
    }

    /**
     * Signs the plaintext, assigns it and updates the text field that shows the signed
     * message in UTF-8.
     */
    private void sign() {
        plainTextToSign = findViewById(R.id.document);
        signedMessage = signature.sign(plainTextToSign.getText().toString().getBytes());
        updateSignedMessageTextField();
    }

    /**
     * Update the signed message upon change.
     */
    private void updateSignedMessageTextField() {
        TextView signedDocument = findViewById(R.id.signedDocument);
        signedDocument.setText(
                new String(Base64.encode(signedMessage, Base64.DEFAULT), StandardCharsets.UTF_8));
    }

    /**
     * Assigns a listener for every button.
     * The first only validates the signature, the second one shows or hides the public key,
     * the third one shuffles the bytes inside and tries to validate it
     * (in order to trigger a false signature) and the fourth one deletes the last bit
     * in order to trigger a RuntimeException.
     */
    private void initButtons() {
        Button validate = (Button) findViewById(R.id.validate);
        Button shuffle = (Button) findViewById(R.id.shuffle);
        Button alter = (Button) findViewById(R.id.alter);
        Button publicKey = (Button) findViewById(R.id.showKey);

        validate.setOnClickListener(view -> {
            // if message has been modified
            updateSignedMessage();
            verifySignedMessage();
        });
        shuffle.setOnClickListener(view -> {
            // if message has been modified
            updateSignedMessage();
            // use the included random number generator
            signedMessage = Rand.randombytes(signedMessage.length);
            isSignedMessageModified = true;
            updateSignedMessageTextField();
            verifySignedMessage();
        });
        alter.setOnClickListener(view -> {
            // if message has been modified
            updateSignedMessage();
            signedMessage = Arrays.copyOf(signedMessage, signedMessage.length + 1);
            isSignedMessageModified = true;
            updateSignedMessageTextField();
            verifySignedMessage();
        });
        publicKey.setOnClickListener(view -> showHidePublicKey());
    }

    /**
     * If a button has modified the signature and another one is pressed after that the message
     * needs to be calculated once again.
     */
    private void updateSignedMessage() {
        // boolean needed, because there is no need to calculate it again (to save time)
        if (isSignedMessageModified) {
            signedMessage = signature.sign(plainTextToSign.getText().toString().getBytes());
            isSignedMessageModified = false;
        }
    }

    /**
     * Tries to verify the signed message with the plain text message, signed message and public key.
     */
    private void verifySignedMessage() {
        byte[] message = plainTextToSign.getText().toString().getBytes();
        TextView isValidated = findViewById(R.id.isValidated);
        if (signedMessage != null) {
            String output;
            try {
                boolean verified = signature.verify(message, signedMessage, publicKey);
                output = verified ? "Signature is valid."
                        : "Signature is not valid, but key and signature length are right.";
            } catch (RuntimeException e) {
                output = "Signature is not valid. " + e.getMessage()
                        + " (RuntimeException was thrown).";
            }
            isValidated.setText(output);
        }
    }

    /**
     * Shows or hides the public key.
     */
    private void showHidePublicKey() {
        TextView publicKeyField = findViewById(R.id.publicKeyField);
        if (publicKeyField.getText().equals("")) {
            isPublicKeyShown = true;
            setPublicKey();
        } else {
            isPublicKeyShown = false;
            publicKeyField.setText("");
        }
    }

    /**
     * Updates the public key if it is shown.
     */
    @SuppressLint("SetTextI18n")
    private void setPublicKey() {
        if (isPublicKeyShown) {
            String publicKeyAsString = new String(
                    Base64.encode(publicKey, Base64.DEFAULT),
                    StandardCharsets.UTF_8);
            TextView publicKeyField = findViewById(R.id.publicKeyField);
            publicKeyField.setText("Public key: " + publicKeyAsString);
        }
    }
}
