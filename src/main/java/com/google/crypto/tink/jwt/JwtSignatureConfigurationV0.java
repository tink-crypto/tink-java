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
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
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

  @AccessesPartialKey
  private static EcdsaPublicKey toEcdsaPublicKey(JwtEcdsaPublicKey publicKey) {
    return publicKey.getEcdsaPublicKey();
  }

  @AccessesPartialKey
  private static EcdsaPrivateKey toEcdsaPrivateKey(JwtEcdsaPrivateKey privateKey)
      throws GeneralSecurityException {
    return privateKey.getEcdsaPrivateKey();
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
  private static RsaSsaPkcs1PrivateKey toRsaSsaPkcs1PrivateKey(
      JwtRsaSsaPkcs1PrivateKey privateKey) {
    return privateKey.getRsaSsaPkcs1PrivateKey();
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
  private static RsaSsaPssPrivateKey toRsaSsaPssPrivateKey(JwtRsaSsaPssPrivateKey privateKey) {
    return privateKey.getRsaSsaPssPrivateKey();
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

  @AccessesPartialKey
  private static RsaSsaPkcs1PublicKey toRsaSsaPkcs1PublicKey(JwtRsaSsaPkcs1PublicKey publicKey) {
    return publicKey.getRsaSsaPkcs1PublicKey();
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

  @AccessesPartialKey
  private static RsaSsaPssPublicKey toRsaSsaPssPublicKey(JwtRsaSsaPssPublicKey publicKey) {
    return publicKey.getRsaSsaPssPublicKey();
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
