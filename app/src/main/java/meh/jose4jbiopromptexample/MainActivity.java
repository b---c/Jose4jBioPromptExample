package meh.jose4jbiopromptexample;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import android.content.Intent;
import androidx.biometric.BiometricPrompt;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {

    public static final String EXTRA_MESSAGE = "meh.jose4jbiopromptexample.MESSAGE";
    public static final String TAG = "j4jex";
    public static final String KEYSTORE_ALIAS_JWS = "key-pair-4JWS";
    public static final String KEYSTORE_ALIAS_JWE = "key-pair-4JWE";
    public static final String ANDROID_KEY_STORE_PROVIDER_NAME = "AndroidKeyStore";

    // private

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initKeys();
    }

    public void doJws(View view) throws Exception {
        EditText editText = findViewById(R.id.editText);
        String message = editText.getText().toString();

        Intent intent = new Intent(this, DisplayMessageActivity.class);

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setDeviceCredentialAllowed(false)
                .setTitle("Biometric Auth Needed to Access Signing Key")
                .setNegativeButtonText("Cancel")
                .build();

        KeyPair keyPair = getKeyPair(KEYSTORE_ALIAS_JWS);

        JsonWebSignature jws = new JsonWebSignature();

        Executor executor = ContextCompat.getMainExecutor(this);


        BiometricPrompt biometricPrompt = new BiometricPrompt(MainActivity.this,
                executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {

                    String signedJws = jws.getCompactSerialization();

                    JsonWebSignature verifyJws = new JsonWebSignature();
                    verifyJws.setCompactSerialization(signedJws);
                    verifyJws.setKey(keyPair.getPublic());
                    boolean signatureVerified = verifyJws.verifySignature();

                    PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keyPair.getPublic());

                    StringBuilder sb = new StringBuilder();
                    sb.append("Message: ").append(verifyJws.getPayload()).append("\n\n");
                    sb.append("JWS: ").append(signedJws).append("\n\n");
                    sb.append("Signature verified: ").append(signatureVerified).append("\n\n");
                    sb.append("JWK: ").append(jwk.toJson());

                    Log.i(TAG, sb.toString());

                    intent.putExtra(EXTRA_MESSAGE, sb.toString());
                    startActivity(intent);

                } catch (JoseException e) {
                    stuffHappens(e, "Problem in JWS verification.");
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "Authentication failed", Toast.LENGTH_SHORT).show();
            }
        });

        jws.setPayload(message);

        jws.setKey(keyPair.getPrivate());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        CryptoPrimitive cryptoPrimitive = jws.prepareSigningPrimitive();
        Signature signature = cryptoPrimitive.getSignature();

        biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(signature));
    }

    public void doJwe(View view) throws Exception {

        EditText editText = findViewById(R.id.editText);
        String message = editText.getText().toString();

        Intent intent = new Intent(this, DisplayMessageActivity.class);

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setDeviceCredentialAllowed(false)
                .setTitle("Biometric Auth Needed to Access Decryption Key")
                .setNegativeButtonText("Nope")
                .build();

        KeyPair encryptionKeyPair = getKeyPair(KEYSTORE_ALIAS_JWE);

        JsonWebEncryption encryptingJwe = new JsonWebEncryption();
        encryptingJwe.setPayload(message);
        encryptingJwe.setKey(encryptionKeyPair.getPublic());
        encryptingJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        encryptingJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        String encryptedJwe = encryptingJwe.getCompactSerialization();

        JsonWebEncryption decryptingJwe = new JsonWebEncryption();
        decryptingJwe.setCompactSerialization(encryptedJwe);
        decryptingJwe.setKey(encryptionKeyPair.getPrivate());

        Executor executor = ContextCompat.getMainExecutor(this);

        BiometricPrompt biometricPrompt = new BiometricPrompt(MainActivity.this,
                executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {

                    String payload = decryptingJwe.getPayload();

                    StringBuilder sb = new StringBuilder();
                    sb.append("Payload: ").append(payload).append("\n\n");
                    sb.append("JWE: ").append(encryptedJwe);

                    Log.i(TAG, sb.toString());

                    intent.putExtra(EXTRA_MESSAGE, sb.toString());
                    startActivity(intent);

                } catch (JoseException e) {
                    stuffHappens(e, "Problem in JWE decryption.");
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "Authentication failed",
                        Toast.LENGTH_SHORT).show();
            }
        });

        decryptingJwe.setDoKeyValidation(false);
        CryptoPrimitive cryptoPrimitive = decryptingJwe.prepareDecryptingPrimitive();
        Cipher cipher = cryptoPrimitive.getCipher();

        biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));

    }

    private KeyPair getKeyPair(String alias) {
        KeyPair kp = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_PROVIDER_NAME);
            keyStore.load(null);
            Enumeration<String> enumeration = keyStore.aliases();
            List<String> aliases = Collections.list(enumeration);
            Log.d(TAG, "KeyStore aliases: " + aliases);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            if (privateKey != null) {
                PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
                kp = new KeyPair(publicKey, privateKey);
            }
        } catch (GeneralSecurityException | IOException e) {
            stuffHappens(e, "Problem accessing key store for alias " + alias);
        }
        Log.d(TAG, "getKeyPair("+alias+"): " + kp);
        return kp;
    }

    private void initKeys()  {
        if (getKeyPair(KEYSTORE_ALIAS_JWS) == null) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE_PROVIDER_NAME);
                kpg.initialize(new KeyGenParameterSpec.Builder(
                        KEYSTORE_ALIAS_JWS,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA512)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(true) // means BiometricPrompt must be used at signing time
                        .setInvalidatedByBiometricEnrollment(true)
                        .build());
                kpg.generateKeyPair();
                Log.d(TAG, "signing key pair generated");
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
                stuffHappens(e, "Problem creating signing key.");
            }
        }

        if (getKeyPair(KEYSTORE_ALIAS_JWE) == null) {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                keyPairGenerator.initialize(
                        new KeyGenParameterSpec.Builder(
                                KEYSTORE_ALIAS_JWE,
                                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                                .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                .setUserAuthenticationRequired(true)
                                .setInvalidatedByBiometricEnrollment(true)
                                .build());

                keyPairGenerator.generateKeyPair();
                Log.d(TAG, "encryption key pair generated");
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
                stuffHappens(e, "Problem creating encryption key.");
            }
        }
    }

    private void stuffHappens(Exception e, String msg) {
        Log.d(TAG, msg, e);
        Toast.makeText(getApplicationContext(), msg, Toast.LENGTH_SHORT).show();
    }
}