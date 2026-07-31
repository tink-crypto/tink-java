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

package com.google.crypto.tink.jwt.internal;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeySign;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code JwtMlDsaPrivateKey} keys and produces new instances of
 * {@code JwtMlDsaPublicKeySign}.
 */
@LowLevelCryptoCaller
public final class JwtMlDsaSignKeyManager {
  private static final PrimitiveConstructor<JwtMlDsaPrivateKey, JwtPublicKeySign>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtMlDsaPublicKeySign::create, JwtMlDsaPrivateKey.class, JwtPublicKeySign.class);

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final KeyCreator<JwtMlDsaParameters> KEY_CREATOR = JwtMlDsaKeyCreator::createKey;

  private JwtMlDsaSignKeyManager() {}

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";
  }

  /**
   * List of default templates to generate tokens with algorithms "ML-DSA-44", "ML-DSA-65" or
   * "ML-DSA-87". Use the template with the "_RAW" suffix if you want to generate tokens without a
   * "kid" header.
   */
  private static Map<String, Parameters> namedParameters() {
    Map<String, Parameters> result = new HashMap<>();
    result.put(
        "JWT_ML_DSA_44_RAW",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44));
    result.put(
        "JWT_ML_DSA_44",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44));
    result.put(
        "JWT_ML_DSA_65_RAW",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65));
    result.put(
        "JWT_ML_DSA_65",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_65));
    result.put(
        "JWT_ML_DSA_87_RAW",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_87));
    result.put(
        "JWT_ML_DSA_87",
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_87));
    return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  /**
   * Registers the {@link JwtMlDsaSignKeyManager} and the {@link JwtMlDsaVerifyKeyManager} with the
   * registry, so that JWT ML-DSA keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtMlDsaParameters.class);
    JwtMlDsaProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(JwtMlDsaVerifyKeyManager.PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
  }
}
