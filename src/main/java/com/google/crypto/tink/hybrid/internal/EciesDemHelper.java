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

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.internal.AesGcmJceUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/** Helper functions for ECIES Data Encryption Mechanism (DEM). */
public final class EciesDemHelper {
  private static final byte[] EMPTY_AAD = new byte[0];

  /** Interface for a DEM. */
  public interface Dem {
    int getSymmetricKeySizeInBytes();

    byte[] encrypt(byte[] demKeyValue, byte[] prefix, byte[] header, byte[] plaintext)
        throws GeneralSecurityException;

    byte[] decrypt(byte[] demKeyValue, byte[] ciphertext, int prefixAndHeaderSize)
        throws GeneralSecurityException;
  }

  private static final class AesGcmDem implements Dem {
    private static final int AES_GCM_IV_SIZE_IN_BYTES = AesGcmJceUtil.IV_SIZE_IN_BYTES;
    private static final int AES_GCM_TAG_SIZE_IN_BYTES = AesGcmJceUtil.TAG_SIZE_IN_BYTES;

    private final int keySizeInBytes;

    public AesGcmDem(AesGcmParameters parameters) throws GeneralSecurityException {
      if (parameters.getIvSizeBytes() != AES_GCM_IV_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("invalid IV size");
      }
      if (parameters.getTagSizeBytes() != AES_GCM_TAG_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("invalid tag size");
      }
      if (parameters.getVariant() != AesGcmParameters.Variant.NO_PREFIX) {
        throw new GeneralSecurityException("invalid variant");
      }
      this.keySizeInBytes = parameters.getKeySizeBytes();
    }

    @Override
    public int getSymmetricKeySizeInBytes() {
      return keySizeInBytes;
    }

    @Override
    public byte[] encrypt(byte[] demKeyValue, byte[] prefix, byte[] header, byte[] plaintext)
        throws GeneralSecurityException {
      if (demKeyValue.length != keySizeInBytes) {
        throw new GeneralSecurityException("invalid key size");
      }
      SecretKey keySpec = AesGcmJceUtil.getSecretKey(demKeyValue);
      byte[] nonce = Random.randBytes(AES_GCM_IV_SIZE_IN_BYTES);
      AlgorithmParameterSpec params = AesGcmJceUtil.getParams(nonce);
      Cipher cipher = AesGcmJceUtil.getThreadLocalCipher();
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
      int outputSize = cipher.getOutputSize(plaintext.length);
      int prefixAndHeaderSize = prefix.length + header.length;
      if (outputSize > Integer.MAX_VALUE - prefixAndHeaderSize - AES_GCM_IV_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("plaintext too long");
      }
      int len = prefixAndHeaderSize + AES_GCM_IV_SIZE_IN_BYTES + outputSize;
      byte[] output = Arrays.copyOf(prefix, len);
      System.arraycopy(
          /* src= */ header,
          /* srcPos= */ 0,
          /* dest= */ output,
          /* destPos= */ prefix.length,
          /* length= */ header.length);
      System.arraycopy(
          /* src= */ nonce,
          /* srcPos= */ 0,
          /* dest= */ output,
          /* destPos= */ prefixAndHeaderSize,
          /* length= */ AES_GCM_IV_SIZE_IN_BYTES);
      int written =
          cipher.doFinal(
              plaintext,
              0,
              plaintext.length,
              output,
              prefixAndHeaderSize + AES_GCM_IV_SIZE_IN_BYTES);
      if (written != outputSize) {
        throw new GeneralSecurityException("not enough data written");
      }
      return output;
    }

    @Override
    public byte[] decrypt(byte[] demKeyValue, byte[] ciphertext, int prefixAndHeaderSize)
        throws GeneralSecurityException {
      if (ciphertext.length < prefixAndHeaderSize) {
        throw new GeneralSecurityException("ciphertext too short");
      }
      if (demKeyValue.length != keySizeInBytes) {
        throw new GeneralSecurityException("invalid key size");
      }
      SecretKey key = AesGcmJceUtil.getSecretKey(demKeyValue);
      if (ciphertext.length
          < prefixAndHeaderSize + AES_GCM_IV_SIZE_IN_BYTES + AES_GCM_TAG_SIZE_IN_BYTES) {
        throw new GeneralSecurityException("ciphertext too short");
      }
      AlgorithmParameterSpec params =
          AesGcmJceUtil.getParams(ciphertext, prefixAndHeaderSize, AES_GCM_IV_SIZE_IN_BYTES);
      Cipher cipher = AesGcmJceUtil.getThreadLocalCipher();
      cipher.init(Cipher.DECRYPT_MODE, key, params);
      int offset = prefixAndHeaderSize + AES_GCM_IV_SIZE_IN_BYTES;
      int len = ciphertext.length - prefixAndHeaderSize - AES_GCM_IV_SIZE_IN_BYTES;
      return cipher.doFinal(ciphertext, offset, len);
    }
  }

  private static final class AesCtrHmacDem implements Dem {
    private final AesCtrHmacAeadParameters parameters;
    private final int keySizeInBytes;

    public AesCtrHmacDem(AesCtrHmacAeadParameters parameters) {
      this.parameters = parameters;
      this.keySizeInBytes = parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes();
    }

    @Override
    public int getSymmetricKeySizeInBytes() {
      return keySizeInBytes;
    }

    @AccessesPartialKey
    private Aead getAead(byte[] symmetricKeyValue) throws GeneralSecurityException {
      byte[] aesCtrKeyValue = Arrays.copyOf(symmetricKeyValue, parameters.getAesKeySizeBytes());
      byte[] hmacKeyValue =
          Arrays.copyOfRange(
              symmetricKeyValue,
              parameters.getAesKeySizeBytes(),
              parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes());
      return EncryptThenAuthenticate.create(
          AesCtrHmacAeadKey.builder()
              .setParameters(parameters)
              .setAesKeyBytes(SecretBytes.copyFrom(aesCtrKeyValue, InsecureSecretKeyAccess.get()))
              .setHmacKeyBytes(SecretBytes.copyFrom(hmacKeyValue, InsecureSecretKeyAccess.get()))
              .build());
    }

    @Override
    public byte[] encrypt(byte[] demKeyValue, byte[] prefix, byte[] header, byte[] plaintext)
        throws GeneralSecurityException {
      byte[] ciphertext = getAead(demKeyValue).encrypt(plaintext, EMPTY_AAD);
      return Bytes.concat(prefix, header, ciphertext);
    }

    @Override
    public byte[] decrypt(byte[] demKeyValue, byte[] ciphertext, int prefixAndHeaderSize)
        throws GeneralSecurityException {
      if (ciphertext.length < prefixAndHeaderSize) {
        throw new GeneralSecurityException("ciphertext too short");
      }
      byte[] demCiphertext = Arrays.copyOfRange(ciphertext, prefixAndHeaderSize, ciphertext.length);
      return getAead(demKeyValue).decrypt(demCiphertext, EMPTY_AAD);
    }
  }

  private static final class AesSivDem implements Dem {
    private final AesSivParameters parameters;
    private final int keySizeInBytes;

    public AesSivDem(AesSivParameters parameters) {
      this.parameters = parameters;
      this.keySizeInBytes = parameters.getKeySizeBytes();
    }

    @Override
    public int getSymmetricKeySizeInBytes() {
      return keySizeInBytes;
    }

    @AccessesPartialKey
    private DeterministicAead getDaead(byte[] symmetricKeyValue) throws GeneralSecurityException {
      return AesSiv.create(
          AesSivKey.builder()
              .setParameters(parameters)
              .setKeyBytes(SecretBytes.copyFrom(symmetricKeyValue, InsecureSecretKeyAccess.get()))
              .build());
    }

    @Override
    public byte[] encrypt(byte[] demKeyValue, byte[] prefix, byte[] header, byte[] plaintext)
        throws GeneralSecurityException {
      byte[] ciphertext = getDaead(demKeyValue).encryptDeterministically(plaintext, EMPTY_AAD);
      return Bytes.concat(prefix, header, ciphertext);
    }

    @Override
    public byte[] decrypt(byte[] demKeyValue, byte[] ciphertext, int prefixAndHeaderSize)
        throws GeneralSecurityException {
      if (ciphertext.length < prefixAndHeaderSize) {
        throw new GeneralSecurityException("ciphertext too short");
      }
      byte[] demCiphertext = Arrays.copyOfRange(ciphertext, prefixAndHeaderSize, ciphertext.length);
      return getDaead(demKeyValue).decryptDeterministically(demCiphertext, EMPTY_AAD);
    }
  }

  /**
   * Returns a DEM based on the given parameters.
   *
   * <p>The caller must ensure that the parameters are valid DEM parameters.
   *
   * @throws GeneralSecurityException if the parameters are not supported.
   */
  public static Dem getDem(EciesParameters parameters) throws GeneralSecurityException {
    Parameters demParameters = parameters.getDemParameters();
    if (demParameters instanceof AesGcmParameters) {
      return new AesGcmDem((AesGcmParameters) demParameters);
    }
    if (demParameters instanceof AesCtrHmacAeadParameters) {
      return new AesCtrHmacDem((AesCtrHmacAeadParameters) demParameters);
    }
    if (demParameters instanceof AesSivParameters) {
      return new AesSivDem((AesSivParameters) demParameters);
    }
    throw new GeneralSecurityException("Unsupported DEM parameters: " + demParameters);
  }

  private EciesDemHelper() {}
}
