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

package com.google.crypto.tink.signature.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import javax.annotation.Nullable;

/**
 * ECDSA verifying with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaVerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] legacyMessageSuffix = new byte[] {0};

  @SuppressWarnings("Immutable")
  private final ECPublicKey publicKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @SuppressWarnings("Immutable")
  @Nullable
  private final Provider provider;

  // This converter is not used with a proto but rather with an ordinary enum type.
  static final EnumTypeProtoConverter<HashType, EcdsaParameters.HashType> HASH_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HashType, EcdsaParameters.HashType>builder()
          .add(HashType.SHA256, EcdsaParameters.HashType.SHA256)
          .add(HashType.SHA384, EcdsaParameters.HashType.SHA384)
          .add(HashType.SHA512, EcdsaParameters.HashType.SHA512)
          .build();
  static final EnumTypeProtoConverter<EcdsaEncoding, EcdsaParameters.SignatureEncoding>
      ENCODING_CONVERTER =
          EnumTypeProtoConverter.<EcdsaEncoding, EcdsaParameters.SignatureEncoding>builder()
              .add(EcdsaEncoding.IEEE_P1363, EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .add(EcdsaEncoding.DER, EcdsaParameters.SignatureEncoding.DER)
              .build();
  static final EnumTypeProtoConverter<CurveType, EcdsaParameters.CurveType> CURVE_TYPE_CONVERTER =
      EnumTypeProtoConverter.<CurveType, EcdsaParameters.CurveType>builder()
          .add(CurveType.NIST_P256, EcdsaParameters.CurveType.NIST_P256)
          .add(CurveType.NIST_P384, EcdsaParameters.CurveType.NIST_P384)
          .add(CurveType.NIST_P521, EcdsaParameters.CurveType.NIST_P521)
          .build();

  public static PublicKeyVerify create(EcdsaPublicKey key) throws GeneralSecurityException {
    Provider provider = ConscryptUtil.providerOrNull();
    return createWithProviderOrNull(key, provider);
  }

  /**
   * Creates a {@link com.google.crypto.tink.PublicKeyVerify} using a {@link
   * java.security.Provider}. The provider should be either the Conscrypt or the OpenJDK provider.
   */
  public static PublicKeyVerify createWithProvider(EcdsaPublicKey key, Provider provider)
      throws GeneralSecurityException {
    if (provider == null) {
      throw new NullPointerException("provider must not be null");
    }
    return createWithProviderOrNull(key, provider);
  }

  @AccessesPartialKey
  public static PublicKeyVerify createWithProviderOrNull(
      EcdsaPublicKey key, @Nullable Provider provider) throws GeneralSecurityException {
    ECParameterSpec ecParams =
        EllipticCurves.getCurveSpec(
            CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType()));
    ECPoint publicPoint = key.getPublicPoint();
    ECPublicKeySpec spec = new ECPublicKeySpec(publicPoint, ecParams);
    KeyFactory keyFactory;
    if (provider != null) {
      keyFactory = KeyFactory.getInstance("EC", provider);
    } else {
      keyFactory = EngineFactory.KEY_FACTORY.getInstance("EC");
    }
    ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(spec);

    return new EcdsaVerifyJce(
        publicKey,
        HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType()),
        ENCODING_CONVERTER.toProtoEnum(key.getParameters().getSignatureEncoding()),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(EcdsaParameters.Variant.LEGACY)
            ? legacyMessageSuffix
            : EMPTY,
        provider);
  }

  private EcdsaVerifyJce(
      final ECPublicKey publicKey,
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

    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.publicKey = publicKey;
    this.encoding = encoding;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
    this.provider = provider;
  }

  public EcdsaVerifyJce(final ECPublicKey publicKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this(publicKey, hash, encoding, EMPTY, EMPTY, ConscryptUtil.providerOrNull());
    EllipticCurvesUtil.checkPointOnCurve(publicKey.getW(), publicKey.getParams().getCurve());
  }

  private Signature getInstance(String signatureAlgorithm) throws GeneralSecurityException {
    if (provider != null) {
      return Signature.getInstance(signatureAlgorithm, provider);
    }
    return EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
  }

  private void noPrefixVerify(final byte[] signature, final byte[] data)
      throws GeneralSecurityException {
    byte[] derSignature = signature;
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = publicKey.getParams().getCurve();
      if (signature.length != 2 * EllipticCurves.fieldSizeInBytes(curve)) {
        throw new GeneralSecurityException("Invalid signature");
      }
      derSignature = EllipticCurves.ecdsaIeee2Der(signature);
    }
    if (!EllipticCurves.isValidDerEncoding(derSignature)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    Signature verifier = getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (messageSuffix.length > 0) {
      verifier.update(messageSuffix);
    }
    boolean verified = false;
    try {
      verified = verifier.verify(derSignature);
    } catch (RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      noPrefixVerify(signature, data);
      return;
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
    noPrefixVerify(signatureNoPrefix, data);
  }
}
