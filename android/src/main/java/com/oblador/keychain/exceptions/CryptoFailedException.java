package com.oblador.keychain.exceptions;

import android.security.keystore.KeyPermanentlyInvalidatedException;

import androidx.annotation.Nullable;

import java.security.GeneralSecurityException;

public class CryptoFailedException extends GeneralSecurityException {
  public CryptoFailedException(String message) {
    super(message);
  }

  public CryptoFailedException(String message, Throwable t) {
    super(message, t);
  }

  public static void reThrowOnError(@Nullable final Throwable error) throws CryptoFailedException, KeyPermanentlyInvalidatedException {
    if(null == error) return;

    if (error instanceof CryptoFailedException)
      throw (CryptoFailedException) error;

    if (error instanceof KeyPermanentlyInvalidatedException)
      throw (KeyPermanentlyInvalidatedException) error;


    throw new CryptoFailedException("Wrapped error: " + error.getMessage(), error);

  }
}
