// Copyright 2026 Google LLC
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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import javax.annotation.Nullable;

/** Creates HPKE keys. */
public final class HpkeKeyCreator {

  /**
   * An {@link EncodedKeySpec} implementation returning "raw" to enable reflection by Conscrypt
   * without strict compile-time coupling.
   */
  public static final class HpkeRawKeySpec extends EncodedKeySpec {
    @SuppressWarnings("UnusedMethod")
    public HpkeRawKeySpec(byte[] encodedKey) {
      super(encodedKey);
    }

    @Override
    public String getFormat() {
      return "raw";
    }
  }

  @AccessesPartialKey
  public static HpkePrivateKey createKey(
      HpkeParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    SecretBytes privateKeyBytes;
    Bytes publicKeyBytes;

    if (parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)) {
      byte[] privateKeyByteArray = X25519.generatePrivateKey();
      privateKeyBytes = SecretBytes.copyFrom(privateKeyByteArray, InsecureSecretKeyAccess.get());
      publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyByteArray));
    } else if (parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
        || parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
        || parameters.getKemId().equals(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)) {
      EllipticCurves.CurveType curveType = HpkeUtil.nistHpkeKemToCurve(parameters.getKemId());
      KeyPair keyPair = EllipticCurves.generateKeyPair(curveType);
      publicKeyBytes =
          Bytes.copyFrom(
              EllipticCurves.pointEncode(
                  curveType,
                  EllipticCurves.PointFormatType.UNCOMPRESSED,
                  ((ECPublicKey) keyPair.getPublic()).getW()));
      privateKeyBytes =
          SecretBytes.copyFrom(
              BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                  ((ECPrivateKey) keyPair.getPrivate()).getS(),
                  HpkeUtil.getEncodedPrivateKeyLength(parameters.getKemId())),
              InsecureSecretKeyAccess.get());
    } else if (parameters.getKemId().equals(HpkeParameters.KemId.X_WING)) {
      Provider conscryptProvider = ConscryptUtil.providerOrNull();
      if (conscryptProvider == null) {
        throw new GeneralSecurityException(
            "Can't generate X-Wing key as Conscrypt is not available");
      }
      try {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XWING", conscryptProvider);
        KeyPair keyPair = kpg.generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
        publicKeyBytes =
            Bytes.copyFrom(
                keyFactory.getKeySpec(keyPair.getPublic(), HpkeRawKeySpec.class).getEncoded());
        privateKeyBytes =
            SecretBytes.copyFrom(
                keyFactory.getKeySpec(keyPair.getPrivate(), HpkeRawKeySpec.class).getEncoded(),
                InsecureSecretKeyAccess.get());
      } catch (Exception e) {
        throw new GeneralSecurityException("Can't generate X-Wing key", e);
      }
    } else {
      throw new GeneralSecurityException("Unknown KEM ID");
    }
    HpkePublicKey publicKey = HpkePublicKey.create(parameters, publicKeyBytes, idRequirement);
    return HpkePrivateKey.create(publicKey, privateKeyBytes);
  }

  private HpkeKeyCreator() {}
}
