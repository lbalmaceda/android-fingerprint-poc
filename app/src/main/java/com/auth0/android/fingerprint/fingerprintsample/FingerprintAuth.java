package com.auth0.android.fingerprint.fingerprintsample;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Created by lbalmaceda on 4/17/17.
 */

@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintAuth extends FingerprintManagerCompat.AuthenticationCallback {
    private static final String TAG = FingerprintAuth.class.getSimpleName();
    private static final String SHARED_PREFERENCES_NAME = "SECRET_STORAGE";
    private static final String ENCRYPTED_PREFIX = "encrypted_";
    private static final String DEFAULT_ALIAS = "secret";

    private final String alias;
    private final FingerprintManagerCompat fingerprintManager;
    private final KeyguardManager keyguardManager;
    private final SharedPreferences sharedPreferences;
    private final Callback callback;

    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private Cipher cipher;
    private CancellationSignal cancellationSignal;

    // constructor
    // label is optional and is used to match the register/authentication. may be overkill but you might use this lib to protect different places of the app
    public FingerprintAuth(@NonNull Context context, @NonNull Callback callback, @Nullable String alias) {
        this.fingerprintManager = FingerprintManagerCompat.from(context);
        this.keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        this.sharedPreferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        this.callback = callback;
        this.alias = alias != null ? alias : DEFAULT_ALIAS;
        assertAvailable();
        setup();
    }

    private void assertAvailable() {
        if (!fingerprintManager.isHardwareDetected()) {
            throw new IllegalStateException("No fingerprint sensor found.");
        }
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            throw new IllegalStateException("No fingerprints enrolled. Add at least one.");
        }
        if (!keyguardManager.isKeyguardSecure()) {
            throw new IllegalStateException("Lock screen must be enabled with Password/PIN/Fingerprint.");
        }
    }

    private void setup() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to instantiate the KeyGenerator", e);
        }

        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    private boolean initCipher(int operationMode) {
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(alias, null);
            cipher.init(operationMode, key, cipher.getParameters());
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to setup Cipher", e);
        }
    }

    private void createKey(boolean invalidateOnBiometricEnrollment) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            keyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            // This is a workaround to avoid crashes on devices whose API level is < 24
            // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
            // visible on API level +24.
            // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
            // which isn't available yet.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidateOnBiometricEnrollment);
            }
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void encrypt(@NonNull String secret) {
        initCipher(Cipher.ENCRYPT_MODE);
        try {
            byte[] encrypted = cipher.doFinal(secret.getBytes());
            String encryptedSecret = new String(encrypted);
            sharedPreferences.edit().putString(ENCRYPTED_PREFIX + alias, encryptedSecret).apply();
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        }
    }

    @Nullable
    private String decrypt(@NonNull Cipher cipher) {
        initCipher(Cipher.DECRYPT_MODE);
        try {
            final String encryptedSecret = sharedPreferences.getString(ENCRYPTED_PREFIX + alias, null);
            if (encryptedSecret == null) {
                return null;
            }
            byte[] decrypted = cipher.doFinal(encryptedSecret.getBytes());
            return new String(decrypted);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Failed to decrypt the data with the generated key." + e.getMessage());
        }
        return null;
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        super.onAuthenticationError(errMsgId, errString);
        callback.onError(new FingerprintAuthException(errString.toString()));
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        String secret = decrypt(result.getCryptoObject().getCipher());
        callback.onAuthenticated(secret);
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        callback.onError(new FingerprintAuthException("Fingerprint not recognized."));
    }

    // register a key with the current user/fingerprints
    // secret: might be null, but will be sent on the authenticated callback when authentication succeeds
    // invalidatedByBiometricEnrollment: if false, the created key will not be invalidated even if a new fingerprint is enrolled
    public void register(@Nullable String secret, boolean invalidateOnBiometricEnrollment) {
        // creates the fingerprint-protected key in the keystore, using the provided label (or a default if none was provided)
        // if not null, saves the secret somewhere using the created keystore key
        createKey(invalidateOnBiometricEnrollment);
        if (secret != null) {
            encrypt(secret);
        }
    }

    public void authenticate() {
        initCipher(Cipher.DECRYPT_MODE);
        cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(new FingerprintManagerCompat.CryptoObject(cipher), 0, cancellationSignal, this, null);
        // check if fingerprint-protected key exists/is available:
        //     --> if key is not available, call callback.onError() and exits
        //     --> if key is available, continue
        // asks for fingerprint
        //     --> on success: unlocks the key, use the key to decrypt the secret (if there was one) and calls callback.onAuthenticated() and exits
        // in any moment, if user cancels, calls callback.onCanceled() and exits
        // if initially there was a secret provided, in any moment the user is allowed to just input it manually
    }

    public void cancelAuthentication() {
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
            cancellationSignal = null;
            if (callback != null) {
                callback.onCanceled();
            }
        }
    }

    public interface Callback {
        void onAuthenticated(@Nullable String secret); // secret might be null, but the callback includes it anyway

        void onCanceled(); // user cancelled

        void onError(Throwable error); // anything might fail but the most common use case for this callback will be when the user removed/changed the registered fingerprints and we cannot authenticate anyone anymore
    }
}
