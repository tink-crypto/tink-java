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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;

/**
 * ECDSA signing with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaSignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] LEGACY_MESSAGE_SUFFIX = new byte[] {0};

  @SuppressWarnings("Immutable")
  private final ECPrivateKey privateKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @SuppressWarnings("Immutable")
  private final Provider provider;

  private EcdsaSignJce(
      final ECPrivateKey privateKey,
      HashType hash,
      EcdsaEncoding encoding,
      byte[] outputPrefix,
      byte[] messageSuffix,
      Provider provider)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto is not available.");
    }

    this.privateKey = privateKey;
    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.encoding = encoding;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
    this.provider = provider;
  }

  public EcdsaSignJce(final ECPrivateKey privateKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this(privateKey, hash, encoding, EMPTY, EMPTY, ConscryptUtil.providerOrNull());
  }

  @AccessesPartialKey
  public static PublicKeySign create(EcdsaPrivateKey key) throws GeneralSecurityException {
    HashType hashType =
        EcdsaVerifyJce.HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType());
    EcdsaEncoding ecdsaEncoding =
        EcdsaVerifyJce.ENCODING_CONVERTER.toProtoEnum(key.getParameters().getSignatureEncoding());
    CurveType curveType =
        EcdsaVerifyJce.CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType());

    Provider provider = ConscryptUtil.providerOrNull();
    ECParameterSpec ecParams = EllipticCurves.getCurveSpec(curveType);
    ECPrivateKeySpec spec =
        new ECPrivateKeySpec(
            key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()), ecParams);
    KeyFactory keyFactory;
    if (provider != null) {
      keyFactory = KeyFactory.getInstance("EC", provider);
    } else {
      keyFactory = EngineFactory.KEY_FACTORY.getInstance("EC");
    }
    ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(spec);

    return new EcdsaSignJce(
        privateKey,
        hashType,
        ecdsaEncoding,
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(EcdsaParameters.Variant.LEGACY)
            ? LEGACY_MESSAGE_SUFFIX
            : EMPTY,
        provider);
  }

  private Signature getInstance(String signatureAlgorithm) throws GeneralSecurityException {
    if (provider != null) {
      return Signature.getInstance(signatureAlgorithm, provider);
    }
    return EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    Signature signer = getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(data);
    if (messageSuffix.length > 0) {
      signer.update(messageSuffix);
    }
    byte[] signature = signer.sign();
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = privateKey.getParams().getCurve();
      signature =
          EllipticCurves.ecdsaDer2Ieee(signature, 2 * EllipticCurves.fieldSizeInBytes(curve));
    }
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}
