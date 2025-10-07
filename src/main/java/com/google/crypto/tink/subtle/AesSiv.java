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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.subtle.DeterministicAeads;
import com.google.crypto.tink.mac.internal.AesUtil;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-SIV, as described in <a href="https://tools.ietf.org/html/rfc5297">RFC 5297</a>.
 *
 * <p>Each AES-SIV key consists of two sub keys. To meet the security requirements of {@link
 * DeterministicAead}, each sub key must be 256 bits. The total size of ASE-SIV keys is then 512
 * bits.
 *
 * @since 1.1.0
 */
public final class AesSiv implements DeterministicAead, DeterministicAeads {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  // Do not support 128-bit keys because it might not provide 128-bit security level in
  // multi-user setting.
  private static final int KEY_SIZE_IN_BYTES = 64;
  private static final byte[] blockZero = new byte[AesUtil.BLOCK_SIZE];
  private static final byte[] blockOne = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x01
  };

  /** The internal AesCmac object for S2V */
  private final Prf cmacForS2V;

  /** The key used for the CTR encryption */
  private final byte[] aesCtrKey;

  private final byte[] outputPrefix;

  @AccessesPartialKey
  public static DeterministicAeads create(AesSivKey key) throws GeneralSecurityException {
    return new AesSiv(
        validateKey(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())),
        key.getOutputPrefix());
  }

  private static final ThreadLocal<Cipher> localAesCtrCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/CTR/NoPadding");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  @AccessesPartialKey
  private static Prf createCmac(byte[] key) throws GeneralSecurityException {
    return PrfAesCmac.create(
        AesCmacPrfKey.create(
            AesCmacPrfParameters.create(key.length),
            SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get())));
  }

  @CanIgnoreReturnValue
  private static byte[] validateKey(final byte[] key) throws GeneralSecurityException {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException(
          "invalid key size: " + key.length + " bytes; key must have 64 bytes");
    }
    return key;
  }

  // Visible for testing.
  AesSiv(final byte[] key, Bytes outputPrefix) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-SIV in FIPS-mode.");
    }

    // allow 32-byte keys for tests.
    if (key.length != 32 && key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException(
          "invalid key size: " + key.length + " bytes; key must have 32 or 64 bytes");
    }

    byte[] k1 = Arrays.copyOfRange(key, 0, key.length / 2);
    this.aesCtrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
    this.cmacForS2V = createCmac(k1);
    this.outputPrefix = outputPrefix.toByteArray();
  }

  public AesSiv(final byte[] key) throws GeneralSecurityException {
    this(validateKey(key), Bytes.copyFrom(new byte[] {}));
  }

  /**
   * s2v per https://tools.ietf.org/html/rfc5297
   *
   * @param s
   * @return s2v(si)
   * @throws GeneralSecurityException
   */
  private byte[] s2v(final byte[]... s) throws GeneralSecurityException {
    if (s.length == 0) {
      // Should never happen with AES-SIV, but we include this for completeness.
      return cmacForS2V.compute(blockOne, AesUtil.BLOCK_SIZE);
    }

    byte[] result = cmacForS2V.compute(blockZero, AesUtil.BLOCK_SIZE);
    for (int i = 0; i < s.length - 1; i++) {
      final byte[] currBlock;
      if (s[i] == null) {
        currBlock = new byte[0];
      } else {
        currBlock = s[i];
      }
      result =
          com.google.crypto.tink.subtle.Bytes.xor(
              AesUtil.dbl(result), cmacForS2V.compute(currBlock, AesUtil.BLOCK_SIZE));
    }
    byte[] lastBlock = s[s.length - 1];
    if (lastBlock.length >= 16) {
      result = com.google.crypto.tink.subtle.Bytes.xorEnd(lastBlock, result);
    } else {
      result =
          com.google.crypto.tink.subtle.Bytes.xor(AesUtil.cmacPad(lastBlock), AesUtil.dbl(result));
    }
    return cmacForS2V.compute(result, AesUtil.BLOCK_SIZE);
  }

  private byte[] encryptInternal(
      final byte[] plaintext, final byte[]... associatedDatas) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - outputPrefix.length - AesUtil.BLOCK_SIZE) {
      throw new GeneralSecurityException("plaintext too long");
    }

    Cipher aesCtr = localAesCtrCipher.get();
    byte[][] s = Arrays.copyOf(associatedDatas, associatedDatas.length + 1);
    s[associatedDatas.length] = plaintext;
    byte[] computedIv = s2v(s);
    byte[] ivForJavaCrypto = computedIv.clone();
    ivForJavaCrypto[8] &= (byte) 0x7F; // 63th bit from the right
    ivForJavaCrypto[12] &= (byte) 0x7F; // 31st bit from the right

    aesCtr.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(this.aesCtrKey, "AES"),
        new IvParameterSpec(ivForJavaCrypto));

    int outputSize = outputPrefix.length + computedIv.length + plaintext.length;
    byte[] output = Arrays.copyOf(outputPrefix, outputSize);
    System.arraycopy(
        /* src= */ computedIv,
        /* srcPos= */ 0,
        /* dest= */ output,
        /* destPos= */ outputPrefix.length,
        /* length= */ computedIv.length);
    int written =
        aesCtr.doFinal(
            plaintext, 0, plaintext.length, output, outputPrefix.length + computedIv.length);
    if (written != plaintext.length) {
      throw new GeneralSecurityException("not enough data written");
    }
    return output;
  }

  @Override
  public byte[] encryptDeterministicallyWithAssociatedDatas(
      final byte[] plaintext, final byte[]... associatedDatas) throws GeneralSecurityException {
      return encryptInternal(plaintext, associatedDatas);
  }

  @Override
  public byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    return encryptInternal(plaintext, associatedData);
  }

  private byte[] decryptInternal(
      final byte[] ciphertext, final byte[]... associatedDatas) throws GeneralSecurityException {
    if (ciphertext.length < AesUtil.BLOCK_SIZE + outputPrefix.length) {
      throw new GeneralSecurityException("Ciphertext too short.");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }

    Cipher aesCtr = localAesCtrCipher.get();

    byte[] expectedIv =
        Arrays.copyOfRange(
            ciphertext, outputPrefix.length, AesUtil.BLOCK_SIZE + outputPrefix.length);

    byte[] ivForJavaCrypto = expectedIv.clone();
    ivForJavaCrypto[8] &= (byte) 0x7F; // 63th bit from the right
    ivForJavaCrypto[12] &= (byte) 0x7F; // 31st bit from the right

    aesCtr.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(this.aesCtrKey, "AES"),
        new IvParameterSpec(ivForJavaCrypto));

    int offset = AesUtil.BLOCK_SIZE + outputPrefix.length;
    int ctrCiphertextLen = ciphertext.length - offset;
    byte[] decryptedPt = aesCtr.doFinal(ciphertext, offset, ctrCiphertextLen);
    if (ctrCiphertextLen == 0 && decryptedPt == null && SubtleUtil.isAndroid()) {
      // On Android KitKat (19) and Lollipop (21), Cipher.doFinal returns a null pointer when the
      // ciphertext is empty, instead of an empty plaintext. Here we attempt to fix this bug. This
      // is safe because if the plaintext is not empty, the next integrity check would reject it.
      decryptedPt = new byte[0];
    }

    byte[][] s = Arrays.copyOf(associatedDatas, associatedDatas.length + 1);
    s[associatedDatas.length] = decryptedPt;
    byte[] computedIv = s2v(s);

    if (com.google.crypto.tink.subtle.Bytes.equal(expectedIv, computedIv)) {
      return decryptedPt;
    } else {
      throw new AEADBadTagException("Integrity check failed.");
    }
  }

  @Override
  public byte[] decryptDeterministicallyWithAssociatedDatas(
      final byte[] ciphertext, final byte[]... associatedDatas) throws GeneralSecurityException {
      return decryptInternal(ciphertext, associatedDatas);
  }

  @Override
  public byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    return decryptInternal(ciphertext, associatedData);
  }
}
