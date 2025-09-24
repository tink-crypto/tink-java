// Copyright 2018 Google LLC
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

package com.google.crypto.tink.signature;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code RsaSsaPkcs1PrivateKey} keys and produces new instances of
 * {@code RsaSsaPkcs1SignJce}.
 */
public final class RsaSsaPkcs1SignKeyManager {
  private static final PrimitiveConstructor<RsaSsaPkcs1PrivateKey, PublicKeySign>
      PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              RsaSsaPkcs1SignJce::create, RsaSsaPkcs1PrivateKey.class, PublicKeySign.class);

  private static final PrimitiveConstructor<RsaSsaPkcs1PublicKey, PublicKeyVerify>
      PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              RsaSsaPkcs1VerifyJce::create, RsaSsaPkcs1PublicKey.class, PublicKeyVerify.class);

  private static final PrivateKeyManager<PublicKeySign> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(),
          PublicKeySign.class,
          com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parser());

  private static final KeyManager<PublicKeyVerify> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          RsaSsaPkcs1VerifyKeyManager.getKeyType(),
          PublicKeyVerify.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  }

  @AccessesPartialKey
  private static RsaSsaPkcs1PrivateKey createKey(
      RsaSsaPkcs1Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
        KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
    RSAKeyGenParameterSpec spec =
        new RSAKeyGenParameterSpec(
            parameters.getModulusSizeBits(),
            new BigInteger(1, parameters.getPublicExponent().toByteArray()));
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Creates RsaSsaPkcs1PublicKey.
    RsaSsaPkcs1PublicKey rsaSsaPkcs1PublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(pubKey.getModulus())
            .setIdRequirement(idRequirement)
            .build();

    // Creates RsaSsaPkcs1PrivateKey.
    return RsaSsaPkcs1PrivateKey.builder()
        .setPublicKey(rsaSsaPkcs1PublicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(privKey.getPrimeP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(privKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(
                privKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(
                privKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final KeyCreator<RsaSsaPkcs1Parameters> KEY_CREATOR =
      RsaSsaPkcs1SignKeyManager::createKey;

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put(
        "RSA_SSA_PKCS1_3072_SHA256_F4", PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4);
    result.put(
        "RSA_SSA_PKCS1_3072_SHA256_F4_RAW",
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build());
    // This is identical to RSA_SSA_PKCS1_3072_SHA256_F4_RAW. It is needed to maintain backward
    // compatibility with SignatureKeyTemplates.
    result.put(
        "RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX",
        PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX);
    result.put(
        "RSA_SSA_PKCS1_4096_SHA512_F4", PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4);
    result.put(
        "RSA_SSA_PKCS1_4096_SHA512_F4_RAW",
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build());
    return result;
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  /**
   * Registers the {@link RsaSsaPkcs1SignKeyManager} and the {@link RsaSsaPkcs1VerifyKeyManager}
   * with the registry, so that the the RsaSsaPkcs1-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA SSA PKCS1 in FIPS-mode, as BoringCrypto module is not available.");
    }
    RsaSsaPkcs1ProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, RsaSsaPkcs1Parameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPrivateKeyManager, FIPS, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPublicKeyManager, FIPS, false);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA256.
   *       <li>Modulus size: 3072 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}.
   *     </ul>
   */
  public static final KeyTemplate rsa3072SsaPkcs1Sha256F4Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(3072)
                    .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA256.
   *       <li>Modulus size: 3072 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix).
   *     </ul>
   */
  public static final KeyTemplate rawRsa3072SsaPkcs1Sha256F4Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(3072)
                    .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA512.
   *       <li>Modulus size: 4096 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}.
   *     </ul>
   */
  public static final KeyTemplate rsa4096SsaPkcs1Sha512F4Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(4096)
                    .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA512.
   *       <li>Modulus size: 4096 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix).
   *     </ul>
   */
  public static final KeyTemplate rawRsa4096SsaPkcs1Sha512F4Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(4096)
                    .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build()));
  }

  private RsaSsaPkcs1SignKeyManager() {}
}
