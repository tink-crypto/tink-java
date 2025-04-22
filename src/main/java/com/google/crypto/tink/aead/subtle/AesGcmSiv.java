// Copyright 2017 Google LLC
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

package com.google.crypto.tink.aead.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import javax.crypto.Cipher;

/**
 * This primitive implements AES-GCM-SIV (as defined in RFC 8452) using JCE.
 *
 * <p>This encryption mode is intended for authenticated encryption with associated data. A major
 * security problem with AES-GCM is that reusing the same nonce twice leaks the authentication key.
 * AES-GCM-SIV on the other hand has been designed to avoid this vulnerability.
 *
 * <p>This encryption requires a JCE provider that supports the <code>AES/GCM-SIV/NoPadding</code>
 * transformation such as <a href="https://conscrypt.org">Conscrypt</a>. using JCE.
 */
@Alpha
public final class AesGcmSiv implements Aead {

  // localAesGcmSivCipher.get() may be null if the cipher returned by EngineFactory is not a valid
  // AES GCM SIV cipher.
  private static final ThreadLocal<Cipher> localAesGcmSivCipher =
      new ThreadLocal<Cipher>() {
        @Nullable
        @Override
        protected Cipher initialValue() {
          try {
            Cipher cipher = EngineFactory.CIPHER.getInstance("AES/GCM-SIV/NoPadding");
            if (!com.google.crypto.tink.aead.internal.AesGcmSiv.isAesGcmSivCipher(cipher)) {
              return null;
            }
            return cipher;
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private static Cipher cipherSupplier() throws GeneralSecurityException {
    try {
      Cipher cipher = localAesGcmSivCipher.get();
      if (cipher == null) {
        throw new GeneralSecurityException("AES GCM SIV cipher is invalid.");
      }
      return cipher;
    } catch (IllegalStateException ex) {
      throw new GeneralSecurityException("AES GCM SIV cipher is not available or is invalid.", ex);
    }
  }

  private final Aead aead;

  @AccessesPartialKey
  public static Aead create(AesGcmSivKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.AesGcmSiv.create(key, AesGcmSiv::cipherSupplier);
  }

  @AccessesPartialKey
  private static Aead createFromRawKey(final byte[] key) throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.AesGcmSiv.create(
        AesGcmSivKey.builder()
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(key.length)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .build(),
        AesGcmSiv::cipherSupplier);
  }

  private AesGcmSiv(Aead aead) {
    this.aead = aead;
  }

  public AesGcmSiv(final byte[] key) throws GeneralSecurityException {
    this(createFromRawKey(key));
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    return this.aead.encrypt(plaintext, associatedData);
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    return this.aead.decrypt(ciphertext, associatedData);
  }
}
