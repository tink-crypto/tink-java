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
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/**
 * A class with functions helping for HPKE implementations based on Android Keystore.
 *
 * <p>It is currently possible (starting with Android 31) to store ECDH P256 keys in
 * AndroidKeystore, and do the DH key exchange part of HPKE on Android Keystore, without the key
 * ever leaving Android Keystore.
 *
 * <p>The goal of this class is to do as much as possible to help this for authenticated HPKE.
 * Hence, it does all of HPKE except the initial DH key agreement.
 */
@Immutable
public final class AuthHpkeHelperForAndroidKeystore {
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;

  @SuppressWarnings("Immutable") // Manually checked
  private final byte[] ourPublicKeyByteArray;

  @SuppressWarnings("Immutable") // Manually checked
  private final byte[] theirPublicKeyByteArray;

  private AuthHpkeHelperForAndroidKeystore(
      HpkeKem kem,
      HpkeKdf kdf,
      HpkeAead aead,
      byte[] ourPublicKeyByteArray,
      byte[] theirPublicKeyByteArray) {
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.ourPublicKeyByteArray = ourPublicKeyByteArray;
    this.theirPublicKeyByteArray = theirPublicKeyByteArray;
  }

  /**
   * Creates a new AuthHpkeHelperForAndroidKeystore object.
   *
   * <p>The public key provided is the one corresponding to the private key which is typically
   * stored in Android Keystore. In other words, this class is only useful if the caller can somehow
   * do the Diffie-Hellman key exchange with the private key corresponding to the public key
   * provided here.
   */
  @AccessesPartialKey
  public static AuthHpkeHelperForAndroidKeystore create(
      HpkePublicKey ourPublicKey, HpkePublicKey theirPublicKey) throws GeneralSecurityException {
    if (!ourPublicKey.getParameters().equals(theirPublicKey.getParameters())) {
      throw new GeneralSecurityException(
          "ourPublicKey.getParameters() must be equal to theirPublicKey.getParameters()");
    }
    HpkeParameters parameters = ourPublicKey.getParameters();
    validateParameters(parameters);
    HpkeKem kem = HpkePrimitiveFactory.createKem(parameters.getKemId());
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(parameters.getKdfId());
    HpkeAead aead = HpkePrimitiveFactory.createAead(parameters.getAeadId());
    return new AuthHpkeHelperForAndroidKeystore(
        kem,
        kdf,
        aead,
        ourPublicKey.getPublicKeyBytes().toByteArray(),
        theirPublicKey.getPublicKeyBytes().toByteArray());
  }

  private static void validateParameters(HpkeParameters parameters)
      throws GeneralSecurityException {
    if (!parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)) {
      throw new GeneralSecurityException(
          "AuthHpkeHelperForAndroidKeystore currently only supports KemId.DHKEM_P256_HKDF_SHA256.");
    }
    if (!parameters.getKdfId().equals(HpkeParameters.KdfId.HKDF_SHA256)) {
      throw new GeneralSecurityException(
          "AuthHpkeHelperForAndroidKeystore currently only supports KdfId.HKDF_SHA256.");
    }
    if (!parameters.getAeadId().equals(HpkeParameters.AeadId.AES_128_GCM)
        && !parameters.getAeadId().equals(HpkeParameters.AeadId.AES_256_GCM)) {
      throw new GeneralSecurityException(
          "AuthHpkeHelperForAndroidKeystore currently only supports AeadId.AES_128_GCM and"
              + " AeadId.AES_256_GCM.");
    }
    if (!parameters.getVariant().equals(HpkeParameters.Variant.NO_PREFIX)) {
      throw new GeneralSecurityException(
          "AuthHpkeHelperForAndroidKeystore currently only supports Variant.NO_PREFIX");
    }
  }

  /**
   * Decrypts a ciphertext.
   *
   * <p>The ciphertext must have been encrypted with the public key used to create this helper
   * object. The encapsulated key must be in encapsulatedKey. dhSharedSecret1 must be the
   * Diffie-Hellman shared secrets computed between the receiver and encapsulated key,
   * dhSharedSecret2 must be the Diffie-Hellman secret between the receiver and the sender key.
   */
  public byte[] decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
      byte[] encapsulatedKey,
      byte[] dhSharedSecret1,
      byte[] dhSharedSecret2,
      byte[] ciphertext,
      int ciphertextOffset,
      byte[] info)
      throws GeneralSecurityException {
    byte[] dhSharedSecret = Bytes.concat(dhSharedSecret1, dhSharedSecret2);
    byte[] derivedSharedSecret =
        NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256)
            .deriveKemSharedSecret(
                dhSharedSecret, encapsulatedKey, ourPublicKeyByteArray, theirPublicKeyByteArray);
    HpkeContext context =
        HpkeContext.createContext(
            HpkeUtil.AUTH_MODE, encapsulatedKey, derivedSharedSecret, kem, kdf, aead, info);
    return context.open(ciphertext, ciphertextOffset, EMPTY_ASSOCIATED_DATA);
  }

  /**
   * Encrypts a message.
   *
   * <p>The message will be encrypted for `theirPublicKeyByteArray` and authenticated with
   * `ourPublicKey`. The value in emphemeralPublicKey must contain the public key piont of an
   * ephemerally generated key. dhSharedSecret1 must be the Diffie-Hellman shared secrets computed
   * between the receiver and emphemeralKey. dhSharedSecret2 must be the Diffie-Hellman secret
   * between the receiver and the sender key.
   */
  public byte[] encryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
      ECPoint emphemeralPublicKey,
      byte[] dhSharedSecret1,
      byte[] dhSharedSecret2,
      byte[] plaintext,
      byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] emphemeralPublicKeyByteArray =
        EllipticCurves.pointEncode(
            EllipticCurves.CurveType.NIST_P256, PointFormatType.UNCOMPRESSED, emphemeralPublicKey);
    byte[] dhSharedSecret = Bytes.concat(dhSharedSecret1, dhSharedSecret2);
    byte[] derivedSharedSecret =
        NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256)
            .deriveKemSharedSecret(
                dhSharedSecret,
                emphemeralPublicKeyByteArray,
                theirPublicKeyByteArray,
                ourPublicKeyByteArray);
    HpkeContext context =
        HpkeContext.createContext(
            HpkeUtil.AUTH_MODE,
            emphemeralPublicKeyByteArray,
            derivedSharedSecret,
            kem,
            kdf,
            aead,
            contextInfo);
    return Bytes.concat(
        emphemeralPublicKeyByteArray, context.seal(plaintext, EMPTY_ASSOCIATED_DATA));
  }
}
