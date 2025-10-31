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
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/**
 * JwtSignatureConfigurationV0 contains the following algorithms for JWT:
 *
 * <ul>
 *   <li>EcdsaSign/Verify
 *   <li>RsaSsaPkcs1Sign/Verify
 *   <li>RsaSsaPssSign/Verify
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
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtRsaSsaPkcs1Sign,
              JwtRsaSsaPkcs1PrivateKey.class,
              JwtPublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtRsaSsaPssSign,
              JwtRsaSsaPssPrivateKey.class,
              JwtPublicKeySign.class));

      // Register {@code JwtPublicKeyVerify} wrapper and concrete primitives.
      JwtPublicKeyVerifyWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtEcdsaVerify,
              JwtEcdsaPublicKey.class,
              JwtPublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtRsaSsaPkcs1Verify,
              JwtRsaSsaPkcs1PublicKey.class,
              JwtPublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              JwtSignatureConfigurationV0::createJwtRsaSsaPssVerify,
              JwtRsaSsaPssPublicKey.class,
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

  @AccessesPartialKey
  private static RsaSsaPkcs1PrivateKey toRsaSsaPkcs1PrivateKey(JwtRsaSsaPkcs1PrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PublicKey publicKey =
        toRsaSsaPkcs1PublicKey(privateKey.getPublicKey());
    return RsaSsaPkcs1PrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrimes(privateKey.getPrimeP(), privateKey.getPrimeQ())
        .setPrivateExponent(privateKey.getPrivateExponent())
        .setPrimeExponents(privateKey.getPrimeExponentP(), privateKey.getPrimeExponentQ())
        .setCrtCoefficient(privateKey.getCrtCoefficient())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPkcs1SignJce.create returns an immutable signer.
  private static JwtPublicKeySign createJwtRsaSsaPkcs1Sign(JwtRsaSsaPkcs1PrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey = toRsaSsaPkcs1PrivateKey(privateKey);
    final PublicKeySign signer = RsaSsaPkcs1SignJce.create(rsaSsaPkcs1PrivateKey);
    String algorithm = privateKey.getParameters().getAlgorithm().getStandardName();
    return rawJwt -> {
      String unsignedCompact =
          JwtFormat.createUnsignedCompact(algorithm, privateKey.getPublicKey().getKid(), rawJwt);
      return JwtFormat.createSignedCompact(
          unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
    };
  }

  @AccessesPartialKey
  private static RsaSsaPssPrivateKey toRsaSsaPssPrivateKey(JwtRsaSsaPssPrivateKey privateKey)
      throws GeneralSecurityException {
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(toRsaSsaPssPublicKey(privateKey.getPublicKey()))
        .setPrimes(privateKey.getPrimeP(), privateKey.getPrimeQ())
        .setPrivateExponent(privateKey.getPrivateExponent())
        .setPrimeExponents(privateKey.getPrimeExponentP(), privateKey.getPrimeExponentQ())
        .setCrtCoefficient(privateKey.getCrtCoefficient())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPssVerifyJce.create returns an immutable verifier.
  private static JwtPublicKeySign createJwtRsaSsaPssSign(JwtRsaSsaPssPrivateKey privateKey)
      throws GeneralSecurityException {
    RsaSsaPssPrivateKey rsaSsaPssPrivateKey = toRsaSsaPssPrivateKey(privateKey);
    final PublicKeySign signer = RsaSsaPssSignJce.create(rsaSsaPssPrivateKey);
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

  // Note: each algorithm defines not just the modulo size, but also the
  // hash length and salt length to use.
  // See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5
  private static RsaSsaPkcs1Parameters.HashType hashTypeForJwtRsaSsaPkcs1Algorithm(
      JwtRsaSsaPkcs1Parameters.Algorithm algorithm) throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)) {
      return RsaSsaPkcs1Parameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)) {
      return RsaSsaPkcs1Parameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)) {
      return RsaSsaPkcs1Parameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  @AccessesPartialKey
  private static RsaSsaPkcs1PublicKey toRsaSsaPkcs1PublicKey(JwtRsaSsaPkcs1PublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters rsaSsaPkcs1Parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(publicKey.getParameters().getModulusSizeBits())
            .setPublicExponent(publicKey.getParameters().getPublicExponent())
            .setHashType(
                hashTypeForJwtRsaSsaPkcs1Algorithm(publicKey.getParameters().getAlgorithm()))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(rsaSsaPkcs1Parameters)
        .setModulus(publicKey.getModulus())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPkcs1VerifyJce.create is immutable.
  private static JwtPublicKeyVerify createJwtRsaSsaPkcs1Verify(JwtRsaSsaPkcs1PublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PublicKey rsaSsaPkcs1PublicKey = toRsaSsaPkcs1PublicKey(publicKey);
    final PublicKeyVerify verifier = RsaSsaPkcs1VerifyJce.create(rsaSsaPkcs1PublicKey);

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

  private static RsaSsaPssParameters.HashType hashTypeForJwtRsaSsaPssAlgorithm(
      JwtRsaSsaPssParameters.Algorithm algorithm) throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return RsaSsaPssParameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return RsaSsaPssParameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return RsaSsaPssParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  private static int saltLengthForPssAlgorithm(JwtRsaSsaPssParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return 32;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return 48;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return 64;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  @AccessesPartialKey
  private static RsaSsaPssPublicKey toRsaSsaPssPublicKey(JwtRsaSsaPssPublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPssParameters rsaSsaPssParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(publicKey.getParameters().getModulusSizeBits())
            .setPublicExponent(publicKey.getParameters().getPublicExponent())
            .setSigHashType(
                hashTypeForJwtRsaSsaPssAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setMgf1HashType(
                hashTypeForJwtRsaSsaPssAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setSaltLengthBytes(saltLengthForPssAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPssPublicKey.builder()
        .setParameters(rsaSsaPssParameters)
        .setModulus(publicKey.getModulus())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPssVerifyJce.create returns an immutable verifier.
  private static JwtPublicKeyVerify createJwtRsaSsaPssVerify(JwtRsaSsaPssPublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPssPublicKey rsaSsaPssPublicKey = toRsaSsaPssPublicKey(publicKey);
    final PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(rsaSsaPssPublicKey);

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
