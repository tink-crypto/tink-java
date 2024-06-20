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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.crypto.tink.hybrid.internal.EciesDemHelper;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and AEAD-DEM (data encapsulation
 * mechanism).
 *
 * @since 1.0.0
 */
public final class EciesAeadHkdfHybridEncrypt implements HybridEncrypt {
  private final EciesHkdfSenderKem senderKem;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final EllipticCurves.PointFormatType ecPointFormat;
  private final EciesDemHelper.Dem dem;
  private final byte[] outputPrefix;

  static final String toHmacAlgo(EciesParameters.HashType hash) throws GeneralSecurityException {
    if (hash.equals(EciesParameters.HashType.SHA1)) {
      return "HmacSha1";
    }
    if (hash.equals(EciesParameters.HashType.SHA224)) {
      return "HmacSha224";
    }
    if (hash.equals(EciesParameters.HashType.SHA256)) {
      return "HmacSha256";
    }
    if (hash.equals(EciesParameters.HashType.SHA384)) {
      return "HmacSha384";
    }
    if (hash.equals(EciesParameters.HashType.SHA512)) {
      return "HmacSha512";
    }
    throw new GeneralSecurityException("hash unsupported for EciesAeadHkdf: " + hash);
  }

  static final EnumTypeProtoConverter<EllipticCurves.CurveType, EciesParameters.CurveType>
      CURVE_TYPE_CONVERTER =
          EnumTypeProtoConverter.<EllipticCurves.CurveType, EciesParameters.CurveType>builder()
              .add(EllipticCurves.CurveType.NIST_P256, EciesParameters.CurveType.NIST_P256)
              .add(EllipticCurves.CurveType.NIST_P384, EciesParameters.CurveType.NIST_P384)
              .add(EllipticCurves.CurveType.NIST_P521, EciesParameters.CurveType.NIST_P521)
              .build();

  static final EnumTypeProtoConverter<EllipticCurves.PointFormatType, EciesParameters.PointFormat>
      POINT_FORMAT_TYPE_CONVERTER =
          EnumTypeProtoConverter
              .<EllipticCurves.PointFormatType, EciesParameters.PointFormat>builder()
              .add(PointFormatType.UNCOMPRESSED, EciesParameters.PointFormat.UNCOMPRESSED)
              .add(PointFormatType.COMPRESSED, EciesParameters.PointFormat.COMPRESSED)
              .add(
                  PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                  EciesParameters.PointFormat.LEGACY_UNCOMPRESSED)
              .build();

  private EciesAeadHkdfHybridEncrypt(
      final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt,
      String hkdfHmacAlgo,
      EllipticCurves.PointFormatType ecPointFormat,
      EciesDemHelper.Dem dem,
      byte[] outputPrefix)
      throws GeneralSecurityException {
    EllipticCurves.checkPublicKey(recipientPublicKey);
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.ecPointFormat = ecPointFormat;
    this.dem = dem;
    this.outputPrefix = outputPrefix;
  }

  @AccessesPartialKey
  public static HybridEncrypt create(EciesPublicKey key) throws GeneralSecurityException {
    EllipticCurves.CurveType curveType =
        CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType());
    ECPublicKey recipientPublicKey =
        EllipticCurves.getEcPublicKey(
            curveType,
            key.getNistCurvePoint().getAffineX().toByteArray(),
            key.getNistCurvePoint().getAffineY().toByteArray());
    byte[] hkdfSalt = new byte[0];
    if (key.getParameters().getSalt() != null) {
      hkdfSalt = key.getParameters().getSalt().toByteArray();
    }
    return new EciesAeadHkdfHybridEncrypt(
        recipientPublicKey,
        hkdfSalt,
        toHmacAlgo(key.getParameters().getHashType()),
        POINT_FORMAT_TYPE_CONVERTER.toProtoEnum(key.getParameters().getNistCurvePointFormat()),
        EciesDemHelper.getDem(key.getParameters()),
        key.getOutputPrefix().toByteArray());
  }

  /**
   * Encrypts {@code plaintext} using {@code contextInfo} as <b>info</b>-parameter of the underlying
   * HKDF.
   *
   * @return resulting ciphertext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    EciesHkdfSenderKem.KemKey kemKey =
        senderKem.generateKey(
            hkdfHmacAlgo, hkdfSalt, contextInfo, dem.getSymmetricKeySizeInBytes(), ecPointFormat);
    return dem.encrypt(kemKey.getSymmetricKey(), outputPrefix, kemKey.getKemBytes(), plaintext);
  }
}
