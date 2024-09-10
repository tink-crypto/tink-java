// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.integration.android;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.ChecksSdkIntAtLeast;
import androidx.annotation.RequiresApi;
import com.google.crypto.tink.Aead;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * API to store and use AEAD keys in the <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>Android Keystore is only supported on Android M (API level 23) or newer.
 *
 * <p>This is not yet part of the public API.
 */
final class AndroidKeystore {

  /**
   * Generates a new 256 bit AES-GCM key in Android Keystore, with the given {@code alias}.
   *
   * <p>Warning: Existing keys with the same {@code alias} will be overwritten.
   */
  @RequiresApi(23)
  public static void generateNewAes256GcmKey(String alias) throws GeneralSecurityException {
    KeyGenParameterSpec spec =
        new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build();
    generateNewKeyWithSpec(spec);
  }

  /**
   * Generates a new key in Android Keystore with the given {@link KeyGenParameterSpec}.
   *
   * <p>This can be used to generate keys with Android Keystore specific properties. It is the
   * user's responsibility to ensure that the values in the {@link KeyGenParameterSpec} are
   * correctly set.
   *
   * <p>Warning: Existing keys with the same {@code alias} will be overwritten.
   */
  @RequiresApi(23)
  public static void generateNewKeyWithSpec(KeyGenParameterSpec spec)
      throws GeneralSecurityException {
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    keyGenerator.init(spec);
    keyGenerator.generateKey();
  }

  /**
   * Returns an {@link Aead} backed by a key in Android Keystore specified by {@code alias}.
   *
   * <p>Waring: Android Keystore can only handle a limited number of requests in parallel. If too
   * many calls are made at the same time, both encrypt or decrypt may fail with a {@link
   * GeneralSecurityException}. But if you avoid calling keystore from many threads at the same
   * time, then such failures are unlikely and retrying is not necessary.
   *
   * <p>See <a
   * href="https://android.googlesource.com/platform/frameworks/base/+/master/keystore/java/android/security/KeyStore2.java"
   * >KeyStore2</a> for more information.
   *
   * <p>If decryption throws a {@link BadPaddingException} (which includes {@link
   * AEADBadTagException}), then the ciphertext is not decryptable and retrying will not help.
   */
  public static Aead getAead(String alias) throws GeneralSecurityException {
    return new AndroidKeystoreAesGcmAead(alias, getAndroidKeyStore());
  }

  /** Deletes a key in Android Keystore if it exists. */
  public static void deleteKey(String alias) throws GeneralSecurityException {
    KeyStore keyStore = getAndroidKeyStore();
    keyStore.deleteEntry(alias);
  }

  /** Returns true if there is a key in Android Keystore. */
  public static boolean hasKey(String alias) throws GeneralSecurityException {
    KeyStore keyStore = getAndroidKeyStore();
    return keyStore.containsAlias(alias);
  }

  private static KeyStore getAndroidKeyStore() throws GeneralSecurityException {
    if (!isAtLeastM()) {
      throw new IllegalStateException("Need Android Keystore on Android M or newer");
    }
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(/* param= */ null);
      return keyStore;
    } catch (IOException ex) {
      throw new GeneralSecurityException(ex);
    }
  }

  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.M)
  private static boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }

  private static final class AndroidKeystoreAesGcmAead implements Aead {
    // All instances of this class use a 12 byte IV and a 16 byte tag.
    private static final int IV_SIZE_IN_BYTES = 12;
    private static final int TAG_SIZE_IN_BYTES = 16;

    private final SecretKey key;

    public AndroidKeystoreAesGcmAead(String alias, KeyStore keyStore)
        throws GeneralSecurityException {
      key = (SecretKey) keyStore.getKey(alias, /* password= */ null);
      if (key == null) {
        throw new InvalidKeyException("Keystore cannot load the key with ID: " + alias);
      }
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      // Check that ciphertext is not longer than the max size of a Java array.
      if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("plaintext too long");
      }
      // ciphertext gets prefixed with the IV of size IV_SIZE_IN_BYTES.
      byte[] ciphertext = new byte[IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES];
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      cipher.updateAAD(associatedData);
      int unusedWritten =
          cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, IV_SIZE_IN_BYTES);
      byte[] iv = cipher.getIV();
      if (iv.length != IV_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("IV has unexpected length");
      }
      System.arraycopy(iv, 0, ciphertext, 0, IV_SIZE_IN_BYTES);
      return ciphertext;
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
        throw new BadPaddingException("ciphertext too short");
      }
      // The first IV_SIZE_IN_BYTES bytes of ciphertext are the IV.
      GCMParameterSpec params =
          new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, ciphertext, 0, IV_SIZE_IN_BYTES);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key, params);
      cipher.updateAAD(associatedData);
      return cipher.doFinal(ciphertext, IV_SIZE_IN_BYTES, ciphertext.length - IV_SIZE_IN_BYTES);
    }
  }

  private AndroidKeystore() {}
}
