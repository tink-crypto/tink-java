// Copyright 2025 Google LLC
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

package com.google.crypto.tink.jwt;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/**
 * JwtSignatureConfigurationV0 contains the following algorithms for JWT:
 *
 * <ul>
 *   <li>EcdsaSign/Verify
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class JwtSignatureConfigurationV0 {
  private JwtSignatureConfigurationV0() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register {@code JwtPublicKeySign} wrapper and concrete primitives.
      JwtPublicKeySignWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtEcdsaSign,
              JwtEcdsaPrivateKey.class,
              JwtPublicKeySign.class));

      // Register {@code JwtPublicKeyVerify} wrapper and concrete primitives.
      JwtPublicKeyVerifyWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtEcdsaVerify,
              JwtEcdsaPublicKey.class,
              JwtPublicKeyVerify.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }


  // The following utility functions are copied from
  // src/main/java/com/google/crypto/tink/jwt/JwtEcdsaSignKeyManager.java.
  private static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.CurveType.NIST_P256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.CurveType.NIST_P384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static EcdsaParameters.HashType getHash(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @AccessesPartialKey
  private static EcdsaPublicKey toEcdsaPublicKey(JwtEcdsaPublicKey publicKey)
      throws GeneralSecurityException {
    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(publicKey.getParameters()))
            .setHashType(getHash(publicKey.getParameters()))
            .build();
    return EcdsaPublicKey.builder()
        .setParameters(ecdsaParameters)
        .setPublicPoint(publicKey.getPublicPoint())
        .build();
  }

  @AccessesPartialKey
  private static EcdsaPrivateKey toEcdsaPrivateKey(JwtEcdsaPrivateKey privateKey)
      throws GeneralSecurityException {
    return EcdsaPrivateKey.builder()
        .setPublicKey(toEcdsaPublicKey(privateKey.getPublicKey()))
        .setPrivateValue(privateKey.getPrivateValue())
        .build();
  }

  @SuppressWarnings("Immutable") // EcdsaVerifyJce.create returns an immutable verifier.
  private static JwtPublicKeySign createJwtEcdsaSign(JwtEcdsaPrivateKey privateKey)
      throws GeneralSecurityException {
    EcdsaPrivateKey ecdsaPrivateKey = toEcdsaPrivateKey(privateKey);
    PublicKeySign signer = EcdsaSignJce.create(ecdsaPrivateKey);
    String algorithm = privateKey.getParameters().getAlgorithm().getStandardName();
    return rawJwt -> {
      String unsignedCompact =
          JwtFormat.createUnsignedCompact(algorithm, privateKey.getPublicKey().getKid(), rawJwt);
      return JwtFormat.createSignedCompact(
          unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
    };
  }

  @SuppressWarnings("Immutable") // EcdsaVerifyJce.create returns an immutable verifier.
  private static JwtPublicKeyVerify createJwtEcdsaVerify(JwtEcdsaPublicKey publicKey)
      throws GeneralSecurityException {
    EcdsaPublicKey ecdsaPublicKey = toEcdsaPublicKey(publicKey);
    final PublicKeyVerify verifier = EcdsaVerifyJce.create(ecdsaPublicKey);

    return (compact, validator) -> {
      JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
      verifier.verify(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
      JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
      JwtFormat.validateHeader(
          parsedHeader,
          publicKey.getParameters().getAlgorithm().getStandardName(),
          publicKey.getKid(),
          publicKey.getParameters().allowKidAbsent());
      RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
      return validator.validate(token);
    };
  }

  /** Returns an instance of the {@code JwtSignatureConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use JwtSignatureConfigurationV0, as BoringCrypto module is needed for FIPS"
              + " compatibility");
    }
    return INTERNAL_CONFIGURATION;
  }
}
