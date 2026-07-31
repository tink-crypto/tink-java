// Copyright 2020 Google LLC
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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.jwt.internal.JwtEcdsaKeyCreator;
import com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeySign;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code JwtEcdsaSignKey} keys and produces new instances of {@code
 * JwtPublicKeySign}.
 */
@LowLevelCryptoCaller
public final class JwtEcdsaSignKeyManager {
  private static final PrivateKeyManager<Void> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(), Void.class, com.google.crypto.tink.proto.JwtEcdsaPrivateKey.parser());

  private static final KeyManager<Void> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          JwtEcdsaVerifyKeyManager.getKeyType(),
          Void.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser());

  private static final PrimitiveConstructor<
          com.google.crypto.tink.jwt.JwtEcdsaPrivateKey, JwtPublicKeySign>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtEcdsaPublicKeySign::create,
              com.google.crypto.tink.jwt.JwtEcdsaPrivateKey.class,
              JwtPublicKeySign.class);

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final KeyCreator<JwtEcdsaParameters> KEY_CREATOR =
      JwtEcdsaKeyCreator::createKey;

  private JwtEcdsaSignKeyManager() {}

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";
  }

  /**
   * List of default templates to generate tokens with algorithms "ES256", "ES384" or "ES512". Use
   * the template with the "_RAW" suffix if you want to generate tokens without a "kid" header.
   */
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put(
        "JWT_ES256_RAW",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_ES256",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    result.put(
        "JWT_ES384_RAW",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_ES384",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    result.put(
        "JWT_ES512_RAW",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build());
    result.put(
        "JWT_ES512",
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build());
    return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto module is not available.");
    }
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPrivateKeyManager, FIPS, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPublicKeyManager, FIPS, false);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtEcdsaParameters.class);
    JwtEcdsaProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(JwtEcdsaVerifyKeyManager.PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
  }
}
