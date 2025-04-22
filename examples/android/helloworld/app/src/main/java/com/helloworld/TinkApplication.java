// Copyright 2017 Google Inc.
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

package com.helloworld;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.integration.android.AndroidKeystore;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import javax.crypto.BadPaddingException;

/** A custom application that initializes the Tink runtime at application startup. */
public class TinkApplication extends Application {
  private static final String PREF_FILE_NAME = "hello_world_pref";
  private static final String TINK_KEYSET_NAME = "hello_world_keyset";
  // The alias of the key encryption key (KEK) in Android Keystore.
  private static final String KEY_ENCRYPTION_KEY_ALIAS = "hello_world_key_encryption_key";

  // We use an empty string as associated data, because the key encryption key is only
  // used to encrypt one keyset.
  // If the same KEK is used to encrypt multiple keysets, then each
  // keyset should have a different associated data.
  private static final byte[] TINK_KEYSET_ASSOCIATED_DATA = new byte[0];
  public Aead aead;

  @Override
  public final void onCreate() {
    super.onCreate();
    try {
      TinkConfig.register();
      KeysetHandle handle = getOrCreateEncryptedKeysetWithRetry();
      aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private KeysetHandle getOrCreateEncryptedKeysetWithRetry() throws GeneralSecurityException {
    // Add retry logic in case of transient Android Keystore errors.
    int retries = 3;
    int maxWaitTimeMillis = 100;
    while (true) {
      try {
        return getOrCreateEncryptedKeyset();
      } catch (GeneralSecurityException e) {
        if (retries <= 0) {
          throw e;
        }
      }
      sleepRandomAmount(maxWaitTimeMillis);
      retries--;
      maxWaitTimeMillis *= 2;
    }
  }

  private static void sleepRandomAmount(int maxWaitTimeMillis) {
    int waitTimeMillis = (int) (Math.random() * maxWaitTimeMillis);
    try {
      Thread.sleep(waitTimeMillis);
    } catch (InterruptedException ex) {
      // Ignored.
    }
  }

  /**
   * Returns a keyset that is stored encrypted in the shared preferences. If the KEK and the
   * encrypted keyset do not exist, they are created.
   *
   * <p>This function is not thread-safe.
   */
  private KeysetHandle getOrCreateEncryptedKeyset() throws GeneralSecurityException {
    SharedPreferences sharedPreferences =
        getApplicationContext().getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE);
    boolean encryptedKeysetExists = sharedPreferences.contains(TINK_KEYSET_NAME);
    boolean keysetEncryptionKeyExists = AndroidKeystore.hasKey(KEY_ENCRYPTION_KEY_ALIAS);
    if (!keysetEncryptionKeyExists && encryptedKeysetExists) {
      // The KEK is missing. This may happen if the phone is restored from a backup.
      // You need to decide how to handle this. You may recover from this by creating a new KEK
      // and a new encrypted keyset, but then you need to delete all data that had been
      // encrypted with the old key.
      throw new IllegalStateException(
          "There exists an encrypted keyset, but the key to decrypt it is missing.");
    }
    if (keysetEncryptionKeyExists && !encryptedKeysetExists) {
      // The KEK exists, but the encrypted keyset is missing. In this example we assume that
      // the KEK is only used to encrypt one keyset, so this should not happen.
      // You need to decide how to handle this. You may recover from this by creating a new
      // encrypted keyset, but then you need to delete all data that had been encrypted with the old
      // key.
      throw new IllegalStateException(
          "There exists a key to decrypt a keyset, but the keyset is missing.");
    }
    if (!keysetEncryptionKeyExists && !encryptedKeysetExists) {
      // First call.
      // Create a new KEK in Android Keystore.
      AndroidKeystore.generateNewAes256GcmKey(KEY_ENCRYPTION_KEY_ALIAS);
      // Create a new keyset. In this example, we create an AEAD key of type AES256_GCM.
      KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
      // Encrypt the keyset with the KEK.
      byte[] encryptedKeyset =
          TinkProtoKeysetFormat.serializeEncryptedKeyset(
              handle,
              AndroidKeystore.getAead(KEY_ENCRYPTION_KEY_ALIAS),
              TINK_KEYSET_ASSOCIATED_DATA);
      // In this example, we store the encrypted keyset in the shared preferences.
      sharedPreferences.edit().putString(TINK_KEYSET_NAME, Hex.encode(encryptedKeyset)).commit();
    }
    try {
      // Read the encrypted keyset from the shared preferences and decrypt it.
      byte[] encryptedKeyset = Hex.decode(sharedPreferences.getString(TINK_KEYSET_NAME, null));
      return TinkProtoKeysetFormat.parseEncryptedKeyset(
          encryptedKeyset,
          AndroidKeystore.getAead(KEY_ENCRYPTION_KEY_ALIAS),
          TINK_KEYSET_ASSOCIATED_DATA);
    } catch (BadPaddingException e) {
      // Note that {@link BadPaddingException} includes {@link AEADBadTagException}.
      // This may happen if the encrypted keyset is corrupted, or if it was encrypted
      // with a different KEK. You need to decide how to handle this. You may recover from
      // this by creating a new encrypted keyset, but then you need to delete all data that had
      // been encrypted with the old key.
      throw new IllegalStateException("Failed to decrypt keyset", e);
    }
  }
}
