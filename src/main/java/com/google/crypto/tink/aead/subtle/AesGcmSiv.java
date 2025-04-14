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

package com.google.crypto.tink.aead.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

  // Test vector from https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.1
  private static final byte[] testPlaintext = Hex.decode("7a806c");
  private static final byte[] testAad = Hex.decode("46bb91c3c5");
  private static final byte[] testKey = Hex.decode("36864200e0eaf5284d884a0e77d31646");
  private static final byte[] testNounce = Hex.decode("bae8e37fc83441b16034566b");
  private static final byte[] testResult = Hex.decode("af60eb711bd85bc1e4d3e0a462e074eea428a8");

  // On Android API version 29 and older, the security provider returns an AES GCM cipher instead
  // an AES GCM SIV cipher. This function tests if we have a correct cipher.
  private static boolean isAesGcmSivCipher(Cipher cipher) {
    try {
      // Use test vector to validate that cipher implements AES GCM SIV.
      AlgorithmParameterSpec params = getParams(testNounce);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(testKey, "AES"), params);
      cipher.updateAAD(testAad);
      byte[] output = cipher.doFinal(testResult, 0, testResult.length);
      return Bytes.equal(output, testPlaintext);
    } catch (GeneralSecurityException ex) {
      return false;
    }
  }

  // localAesGcmSivCipher.get() may be null if the cipher returned by EngineFactory is not a valid
  // AES GCM SIV cipher.
  private static final ThreadLocal<Cipher> localAesGcmSivCipher =
      new ThreadLocal<Cipher>() {
        @Nullable
        @Override
        protected Cipher initialValue() {
          try {
            Cipher cipher = EngineFactory.CIPHER.getInstance("AES/GCM-SIV/NoPadding");
            if (!isAesGcmSivCipher(cipher)) {
              return null;
            }
            return cipher;
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  // All instances of this class use a 12 byte IV and a 16 byte tag.
  private static final int IV_SIZE_IN_BYTES = 12;
  private static final int TAG_SIZE_IN_BYTES = 16;

  private final SecretKey keySpec;
  private final byte[] outputPrefix;

  @AccessesPartialKey
  public static Aead create(AesGcmSivKey key) throws GeneralSecurityException {
    return new AesGcmSiv(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix().toByteArray());
  }

  private AesGcmSiv(byte[] key, byte[] outputPrefix) throws GeneralSecurityException {
    this.outputPrefix = outputPrefix;
    Validators.validateAesKeySize(key.length);
    keySpec = new SecretKeySpec(key, "AES");
  }

  public AesGcmSiv(final byte[] key) throws GeneralSecurityException {
    this(key, new byte[0]);
  }

  private Cipher getAesGcmSivCipher() throws GeneralSecurityException {
    Cipher cipher = localAesGcmSivCipher.get();
    if (cipher == null) {
      throw new GeneralSecurityException("AES GCM SIV cipher is not available or is invalid.");
    }
    return cipher;
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    Cipher cipher = getAesGcmSivCipher();
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length
        > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES - outputPrefix.length) {
      throw new GeneralSecurityException("plaintext too long");
    }

    int ciphertextLen =
        outputPrefix.length + IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES;
    byte[] ciphertext = Arrays.copyOf(outputPrefix, ciphertextLen);
    byte[] iv = Random.randBytes(IV_SIZE_IN_BYTES);
    System.arraycopy(
        /* src= */ iv,
        /* srcPos= */ 0,
        /* dest= */ ciphertext,
        /* destPos= */ outputPrefix.length,
        /* length= */ IV_SIZE_IN_BYTES);

    AlgorithmParameterSpec params = getParams(iv);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int written =
        cipher.doFinal(
            plaintext, 0, plaintext.length, ciphertext, outputPrefix.length + IV_SIZE_IN_BYTES);
    // AES-GCM-SIV always adds a tag of length TAG_SIZE_IN_BYTES.
    if (written != plaintext.length + TAG_SIZE_IN_BYTES) {
      int actualTagSize = written - plaintext.length;
      throw new GeneralSecurityException(
          String.format(
              "encryption failed; AES-GCM-SIV tag must be %s bytes, but got only %s bytes",
              TAG_SIZE_IN_BYTES, actualTagSize));
    }
    return ciphertext;
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < outputPrefix.length + IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    Cipher cipher = getAesGcmSivCipher();
    AlgorithmParameterSpec params = getParams(ciphertext, outputPrefix.length, IV_SIZE_IN_BYTES);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int offset = outputPrefix.length + IV_SIZE_IN_BYTES;
    int len = ciphertext.length - outputPrefix.length - IV_SIZE_IN_BYTES;
    return cipher.doFinal(ciphertext, offset, len);
  }

  private static AlgorithmParameterSpec getParams(final byte[] iv) {
    return getParams(iv, 0, iv.length);
  }

  private static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len) {
    return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, buf, offset, len);
  }
}
