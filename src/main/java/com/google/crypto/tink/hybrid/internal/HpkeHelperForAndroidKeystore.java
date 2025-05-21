// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;

/**
 * A class with functions helping for HPKE implementations based on Android Keystore.
 *
 * <p>It is currently possible (starting with Android 31) to store ECDH P256 keys in
 * AndroidKeystore, and do the DH key exchange part of HPKE on Android Keystore, without the key
 * ever leaving Android Keystore.
 *
 * <p>The goal of this class is to do as much as possible to help this. Hence, it does all of HPKE
 * except the initial DH key agreement.
 */
public final class HpkeHelperForAndroidKeystore {
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;
  private final byte[] publicKeyByteArray;

  private HpkeHelperForAndroidKeystore(
      HpkeKem kem, HpkeKdf kdf, HpkeAead aead, byte[] publicKeyByteArray) {
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.publicKeyByteArray = publicKeyByteArray;
  }

  /**
   * Creates a new HpkeHelperForAndroidKeystore object.
   *
   * <p>The public key provided is the one corresponding to the private key which is typically
   * stored in Android Keystore. In other words, this class is only useful if the caller can somehow
   * do the Diffie-Hellman key exchange with the private key corresponding to the public key
   * provided here.
   */
  @AccessesPartialKey
  public static HpkeHelperForAndroidKeystore create(HpkePublicKey receiverPublicKey)
      throws GeneralSecurityException {
    HpkeParameters parameters = receiverPublicKey.getParameters();
    validateParameters(parameters);
    HpkeKem kem = HpkePrimitiveFactory.createKem(parameters.getKemId());
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(parameters.getKdfId());
    HpkeAead aead = HpkePrimitiveFactory.createAead(parameters.getAeadId());
    return new HpkeHelperForAndroidKeystore(
        kem, kdf, aead, receiverPublicKey.getPublicKeyBytes().toByteArray());
  }

  private static void validateParameters(HpkeParameters parameters)
      throws GeneralSecurityException {
    if (!parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)) {
      throw new GeneralSecurityException(
          "HpkeHelperForAndroidKeystore currently only supports DHKEM_P256_HKDF_SHA256.");
    }
    if (!parameters.getKdfId().equals(HpkeParameters.KdfId.HKDF_SHA256)) {
      throw new GeneralSecurityException(
          "HpkeHelperForAndroidKeystore currently only supports HKDF_SHA256.");
    }
    if (!parameters.getAeadId().equals(HpkeParameters.AeadId.AES_128_GCM)) {
      throw new GeneralSecurityException(
          "HpkeHelperForAndroidKeystore currently only supports AES_128_GCM.");
    }
    if (!parameters.getVariant().equals(HpkeParameters.Variant.NO_PREFIX)) {
      throw new GeneralSecurityException(
          "HpkeHelperForAndroidKeystore currently only supports Variant.NO_PREFIX");
    }
  }

  /**
   * Decrypts a ciphertext.
   *
   * <p>The ciphertext must have been encrypted with the public key used to create this helper
   * object. The encapsulated key must be in encapsulatedKey. The dhSharedSecret must be the shared
   * secret computed from the private key and the encapsulated key.
   */
  public byte[] decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(
      byte[] encapsulatedKey,
      byte[] dhSharedSecret,
      byte[] ciphertext,
      int ciphertextOffset,
      byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] info = contextInfo;
    if (info == null) {
      info = new byte[0];
    }

    byte[] sharedSecret =
        NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256)
            .deriveKemSharedSecret(dhSharedSecret, encapsulatedKey, publicKeyByteArray);
    HpkeContext context =
        HpkeContext.createContext(
            HpkeUtil.BASE_MODE, encapsulatedKey, sharedSecret, kem, kdf, aead, info);
    return context.open(ciphertext, ciphertextOffset, EMPTY_ASSOCIATED_DATA);
  }
}
