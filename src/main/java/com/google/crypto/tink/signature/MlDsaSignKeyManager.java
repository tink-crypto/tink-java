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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.internal.MlDsaKeyCreator;
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * This key manager generates new {@code MlDsaPrivateKey} keys and some named parameters.
 *
 * NOTE: in order for the key generation functionality to work, one needs to have a version
 * of Conscrypt installed that supports ML-DSA.
 */
public final class MlDsaSignKeyManager {

  static String getPublicKeyType() {
    return "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";
  }

  static String getPrivateKeyType() {
    return "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  }

  private static final KeyCreator<MlDsaParameters> KEY_CREATOR = MlDsaKeyCreator::createKey;
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    return Map.of(
        "ML_DSA_44",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.TINK),
        "ML_DSA_44_RAW",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX),
        "ML_DSA_65",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK),
        "ML_DSA_65_RAW",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX),
        "ML_DSA_87",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.TINK),
        "ML_DSA_87_RAW",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX));
  }

  /**
   * Registers the {@link MlDsaProtoSerialization}, named parameters, and the key (pair) creator.
   */
  public static void registerPair() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    MlDsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, MlDsaParameters.class);
  }

  private MlDsaSignKeyManager() {}
}
