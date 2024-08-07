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
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.internal.EciesDemHelper;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and AEAD-DEM (data encapsulation
 * mechanism).
 *
 * @since 1.0.0
 */
public final class EciesAeadHkdfHybridDecrypt implements HybridDecrypt {
  private final ECPrivateKey recipientPrivateKey;
  private final EciesHkdfRecipientKem recipientKem;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final EllipticCurves.PointFormatType ecPointFormat;
  private final EciesDemHelper.Dem dem;
  private final byte[] outputPrefix;

  private EciesAeadHkdfHybridDecrypt(
      final ECPrivateKey recipientPrivateKey,
      final byte[] hkdfSalt,
      String hkdfHmacAlgo,
      EllipticCurves.PointFormatType ecPointFormat,
      EciesDemHelper.Dem dem,
      byte[] outputPrefix) {
    this.recipientPrivateKey = recipientPrivateKey;
    this.recipientKem = new EciesHkdfRecipientKem(recipientPrivateKey);
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.ecPointFormat = ecPointFormat;
    this.dem = dem;
    this.outputPrefix = outputPrefix;
  }

  @AccessesPartialKey
  public static HybridDecrypt create(EciesPrivateKey key) throws GeneralSecurityException {
    EllipticCurves.CurveType curveType =
        EciesAeadHkdfHybridEncrypt.CURVE_TYPE_CONVERTER.toProtoEnum(
            key.getParameters().getCurveType());
    ECPrivateKey recipientPrivateKey =
        EllipticCurves.getEcPrivateKey(
            curveType,
            BigIntegerEncoding.toBigEndianBytes(
                key.getNistPrivateKeyValue().getBigInteger(InsecureSecretKeyAccess.get())));
    byte[] hkdfSalt = new byte[0];
    if (key.getParameters().getSalt() != null) {
      hkdfSalt = key.getParameters().getSalt().toByteArray();
    }
    return new EciesAeadHkdfHybridDecrypt(
        recipientPrivateKey,
        hkdfSalt,
        EciesAeadHkdfHybridEncrypt.toHmacAlgo(key.getParameters().getHashType()),
        EciesAeadHkdfHybridEncrypt.POINT_FORMAT_TYPE_CONVERTER.toProtoEnum(
            key.getParameters().getNistCurvePointFormat()),
        EciesDemHelper.getDem(key.getParameters()),
        key.getOutputPrefix().toByteArray());
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Invalid ciphertext (output prefix mismatch)");
    }
    int prefixSize = outputPrefix.length;
    EllipticCurve curve = recipientPrivateKey.getParams().getCurve();
    int headerSize = EllipticCurves.encodingSizeInBytes(curve, ecPointFormat);
    if (ciphertext.length < prefixSize + headerSize) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] kemBytes = Arrays.copyOfRange(ciphertext, prefixSize, prefixSize + headerSize);
    byte[] symmetricKey =
        recipientKem.generateKey(
            kemBytes,
            hkdfHmacAlgo,
            hkdfSalt,
            contextInfo,
            dem.getSymmetricKeySizeInBytes(),
            ecPointFormat);
    return dem.decrypt(symmetricKey, ciphertext, prefixSize + headerSize);
  }
}
