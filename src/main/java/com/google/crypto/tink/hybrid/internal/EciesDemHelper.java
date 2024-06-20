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
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;

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
    private final AesGcmParameters parameters;
    private final int keySizeInBytes;

    public AesGcmDem(AesGcmParameters parameters) {
      this.parameters = parameters;
      this.keySizeInBytes = parameters.getKeySizeBytes();
    }

    @Override
    public int getSymmetricKeySizeInBytes() {
      return keySizeInBytes;
    }

    @AccessesPartialKey
    private Aead getAead(byte[] symmetricKeyValue) throws GeneralSecurityException {
      return AesGcmJce.create(
          AesGcmKey.builder()
              .setParameters(parameters)
              .setKeyBytes(SecretBytes.copyFrom(symmetricKeyValue, InsecureSecretKeyAccess.get()))
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
