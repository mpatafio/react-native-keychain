package com.oblador.keychain.decryptionHandler;

import android.os.Looper;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.AssertionException;
import com.facebook.react.bridge.ReactApplicationContext;
import com.oblador.keychain.DeviceAvailability;
import com.oblador.keychain.cipherStorage.CipherStorage;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResult;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionContext;
import com.oblador.keychain.cipherStorage.CipherStorageBase;
import com.oblador.keychain.exceptions.CryptoFailedException;

import java.security.InvalidKeyException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

public class DecryptionResultHandlerInteractiveBiometric extends BiometricPrompt.AuthenticationCallback implements DecryptionResultHandler {
  protected CipherStorage.DecryptionResult result;
  protected Throwable error;
  protected final ReactApplicationContext reactContext;
  protected final CipherStorageBase storage;
  protected final Executor executor = Executors.newSingleThreadExecutor();
  protected CipherStorage.DecryptionContext context;
  protected BiometricPrompt.PromptInfo promptInfo;

  /** Logging tag. */
  protected static final String LOG_TAG = DecryptionResultHandlerInteractiveBiometric.class.getSimpleName();

  public DecryptionResultHandlerInteractiveBiometric(
                                                     @NonNull ReactApplicationContext reactContext,
                                                     @NonNull final CipherStorage storage,
                                                     @NonNull final BiometricPrompt.PromptInfo promptInfo) {
    this.reactContext = reactContext;
    this.storage = (CipherStorageBase) storage;
    this.promptInfo = promptInfo;
  }

  @Override
  public void askAccessPermissions(@NonNull final DecryptionContext context) {
    this.context = context;

    if (!DeviceAvailability.isPermissionsGranted(reactContext)) {
      final CryptoFailedException failure = new CryptoFailedException(
        "Could not start fingerprint Authentication. No permissions granted.");

      onDecrypt(null, failure);
    } else {
      startAuthentication();
    }
  }

  @Override
  public void onDecrypt(@Nullable final DecryptionResult decryptionResult, @Nullable final Throwable error) {
    this.result = decryptionResult;
    this.error = error;

    synchronized (this) {
      notifyAll();
    }
  }

  @Nullable
  @Override
  public CipherStorage.DecryptionResult getResult() {
    return result;
  }

  @Nullable
  @Override
  public Throwable getError() {
    return error;
  }

  /** Called when an unrecoverable error has been encountered and the operation is complete. */
  @Override
  public void onAuthenticationError(final int errorCode, @NonNull final CharSequence errString) {
    final CryptoFailedException error = new CryptoFailedException("code: " + errorCode + ", msg: " + errString);

    onDecrypt(null, error);
  }

  /** Called when a biometric is recognized. */
  @Override
  public void onAuthenticationSucceeded(@NonNull final BiometricPrompt.AuthenticationResult result) {
    try {
      if(result.getCryptoObject() != null){
        // the user is trying to decrypt using a new key (bound to a biometric factor)
        final CipherStorage.DecryptionResult decrypted = new CipherStorage.DecryptionResult(
          new String(context.username),
          new String(result.getCryptoObject().getCipher().doFinal(context.password))
        );
        onDecrypt(decrypted, null);
      } else {
        // the user is trying to decrypt using an old key (not bound to a biometric factor)
        final CipherStorage.DecryptionResult decrypted = new CipherStorage.DecryptionResult(
          storage.decryptBytes(context.key, context.username),
          storage.decryptBytes(context.key, context.password)
        );
        onDecrypt(decrypted, null);
      }
    } catch (Throwable fail) {
      onDecrypt(null, fail);
    }
  }

  /** trigger interactive authentication. */
  public void startAuthentication() {
    FragmentActivity activity = getCurrentActivity();

    // code can be executed only from MAIN thread
    if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
      activity.runOnUiThread(this::startAuthentication);
      waitResult();
      return;
    }

    authenticateWithPrompt(activity);
  }

  protected FragmentActivity getCurrentActivity() {
    final FragmentActivity activity = (FragmentActivity) reactContext.getCurrentActivity();
    if (null == activity) throw new NullPointerException("Not assigned current activity");

    return activity;
  }

  protected BiometricPrompt authenticateWithPrompt(@NonNull final FragmentActivity activity) {
    final BiometricPrompt prompt = new BiometricPrompt(activity, executor, this);
    try {
      this.storage.getCachedInstance().init(Cipher.DECRYPT_MODE, context.key);
      prompt.authenticate(this.promptInfo, new BiometricPrompt.CryptoObject(this.storage.getCachedInstance()));
    }
    catch (final UserNotAuthenticatedException userNotAuthenticatedException){
      Log.i(LOG_TAG, "User not authenticated, the user is likely migrating from an old key.");
      prompt.authenticate(this.promptInfo);
    }
    catch (final InvalidKeyException invalidKeyException) {
      Log.i(LOG_TAG, "Key has been invalidated.");
      this.onDecrypt(null, invalidKeyException);
    }
    catch (final Throwable fail) {
      // any other exception treated as a failure
      this.onDecrypt(null, fail);
    }
    return prompt;
  }

  /** Block current NON-main thread and wait for user authentication results. */
  @Override
  public void waitResult() {
    if (Thread.currentThread() == Looper.getMainLooper().getThread())
      throw new AssertionException("method should not be executed from MAIN thread");

    Log.i(LOG_TAG, "blocking thread. waiting for done UI operation.");

    try {
      synchronized (this) {
        wait();
      }
    } catch (InterruptedException ignored) {
      /* shutdown sequence */
    }

    Log.i(LOG_TAG, "unblocking thread.");
  }
}
