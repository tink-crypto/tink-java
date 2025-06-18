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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.prf.Prf;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements the EAX mode using AES.
 *
 * <p>EAX is an encryption mode proposed by Bellare, Rogaway and Wagner
 * (http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf). The encryption mode is an alternative to CCM
 * and has been proposed as a NIST standard:
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf
 *
 * <p>The parameter choices have been restricted to a small set of options:
 *
 * <ul>
 *   <li>The tag size is always 16 bytes
 *   <li>Nonces are chosen by the implementation at random. Their size is 12 or 16 bytes.
 * </ul>
 */
public final class AesEaxJce implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final ThreadLocal<Cipher> localCtrCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/CTR/NOPADDING");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  static final int BLOCK_SIZE_IN_BYTES = 16;
  static final int TAG_SIZE_IN_BYTES = 16;

  private final byte[] outputPrefix;

  private final Prf cmac;
  private final SecretKeySpec keySpec;
  private final int ivSizeInBytes;

  @AccessesPartialKey
  @SuppressWarnings("InsecureCryptoUsage")
  public static Aead create(AesEaxKey key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-EAX in FIPS-mode.");
    }
    if (key.getParameters().getTagSizeBytes() != TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException(
          "AesEaxJce only supports 16 byte tag size, not " + key.getParameters().getTagSizeBytes());
    }
    return new AesEaxJce(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getParameters().getIvSizeBytes(),
        key.getOutputPrefix().toByteArray());
  }

  @AccessesPartialKey
  private static Prf createCmac(byte[] key) throws GeneralSecurityException {
    return new PrfAesCmac(key);
  }

  private AesEaxJce(final byte[] key, int ivSizeInBytes, byte[] outputPrefix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-EAX in FIPS-mode.");
    }

    if (ivSizeInBytes != 12 && ivSizeInBytes != 16) {
      throw new IllegalArgumentException("IV size should be either 12 or 16 bytes");
    }
    this.ivSizeInBytes = ivSizeInBytes;
    Validators.validateAesKeySize(key.length);
    keySpec = new SecretKeySpec(key, "AES");
    cmac = createCmac(key);
    this.outputPrefix = outputPrefix;
  }

  public AesEaxJce(final byte[] key, int ivSizeInBytes) throws GeneralSecurityException {
    this(key, ivSizeInBytes, new byte[0]);
  }

  /**
   * Computes an OMAC.
   *
   * <p>OMAC (or OMAC1) is the same as to CMAC, where the tag is prepended to the data.
   *
   * @param tag The OMAC tag (0 for nonce, 1 for aad, 2 for ciphertext)
   * @param data The array containing the data to MAC.
   * @param offset The start of the data to MAC.
   * @param length The length of the data to MAC.
   * @return The 16 byte long OMAC
   * @throws GeneralSecurityException This should not happen.
   */
  private byte[] omac(int tag, final byte[] data, int offset, int length)
      throws GeneralSecurityException {
    byte[] input = new byte[length + BLOCK_SIZE_IN_BYTES];
    input[BLOCK_SIZE_IN_BYTES - 1] = (byte) tag;
    System.arraycopy(
        /* src= */ data,
        /* srcPos= */ offset,
        /* dest= */ input,
        /* destPos= */ BLOCK_SIZE_IN_BYTES,
        /* length= */ length);
    return cmac.compute(input, BLOCK_SIZE_IN_BYTES);
  }

  @SuppressWarnings("InsecureCryptoUsage")
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length
        > Integer.MAX_VALUE - outputPrefix.length - ivSizeInBytes - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] ciphertext =
        Arrays.copyOf(
            outputPrefix,
            outputPrefix.length + ivSizeInBytes + plaintext.length + TAG_SIZE_IN_BYTES);
    byte[] iv = Random.randBytes(ivSizeInBytes);
    System.arraycopy(
        /* src= */ iv,
        /* srcPos= */ 0,
        /* dest= */ ciphertext,
        /* destPos= */ outputPrefix.length,
        /* length= */ ivSizeInBytes);
    byte[] n = omac(0, iv, 0, iv.length);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] h = omac(1, aad, 0, aad.length);
    Cipher ctr = localCtrCipher.get();
    ctr.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(n));
    ctr.doFinal(plaintext, 0, plaintext.length, ciphertext, outputPrefix.length + ivSizeInBytes);
    byte[] t = omac(2, ciphertext, outputPrefix.length + ivSizeInBytes, plaintext.length);
    int offset = outputPrefix.length + plaintext.length + ivSizeInBytes;
    for (int i = 0; i < TAG_SIZE_IN_BYTES; i++) {
      ciphertext[offset + i] = (byte) (h[i] ^ n[i] ^ t[i]);
    }
    return ciphertext;
  }

  @SuppressWarnings("InsecureCryptoUsage")
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    int plaintextLength =
        ciphertext.length - outputPrefix.length - ivSizeInBytes - TAG_SIZE_IN_BYTES;
    if (plaintextLength < 0) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    byte[] n = omac(0, ciphertext, outputPrefix.length, ivSizeInBytes);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] h = omac(1, aad, 0, aad.length);
    byte[] t = omac(2, ciphertext, outputPrefix.length + ivSizeInBytes, plaintextLength);
    byte res = 0;
    int offset = ciphertext.length - TAG_SIZE_IN_BYTES;
    for (int i = 0; i < TAG_SIZE_IN_BYTES; i++) {
      res = (byte) (res | (ciphertext[offset + i] ^ h[i] ^ n[i] ^ t[i]));
    }
    if (res != 0) {
      throw new AEADBadTagException("tag mismatch");
    }
    Cipher ctr = localCtrCipher.get();
    ctr.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(n));
    return ctr.doFinal(ciphertext, outputPrefix.length + ivSizeInBytes, plaintextLength);
  }
}
