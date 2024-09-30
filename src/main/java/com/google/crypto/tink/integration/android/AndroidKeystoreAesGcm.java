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

package com.google.crypto.tink.integration.android;

import android.util.Log;
import com.google.crypto.tink.Aead;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import javax.crypto.BadPaddingException;

/**
 * An {@link Aead} that does AES-GCM encryption with a key stored in <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>We don't recommend using this class. Instead, directly use {@link AndroidKeystore#getAead} and
 * implement retries yourself if you need them.
 *
 * <p>This class requires Android M (API level 23) or newer.
 *
 * @since 1.0.0
 */
public final class AndroidKeystoreAesGcm implements Aead {
  private static final String TAG = AndroidKeystoreAesGcm.class.getSimpleName();
  private static final int MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY = 100;

  private final Aead keystoreAead;

  public AndroidKeystoreAesGcm(String keyId) throws GeneralSecurityException, IOException {
    this.keystoreAead = AndroidKeystore.getAead(keyId);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      return keystoreAead.encrypt(plaintext, associatedData);
    } catch (ProviderException | GeneralSecurityException ex) {
      Log.w(TAG, "encountered a potentially transient KeyStore error, will wait and retry", ex);
      sleepRandomAmount();
      return keystoreAead.encrypt(plaintext, associatedData);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      return keystoreAead.decrypt(ciphertext, associatedData);
    } catch (BadPaddingException ex) {
      // ciphertext is invalid. There is no point in retrying.
      throw ex;
    } catch (ProviderException | GeneralSecurityException ex) {
      Log.w(TAG, "encountered a potentially transient KeyStore error, will wait and retry", ex);
      sleepRandomAmount();
      return keystoreAead.decrypt(ciphertext, associatedData);
    }
  }

  private static void sleepRandomAmount() {
    int waitTimeMillis = (int) (Math.random() * MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY);
    try {
      Thread.sleep(waitTimeMillis);
    } catch (InterruptedException ex) {
      // Ignored.
    }
  }
}
