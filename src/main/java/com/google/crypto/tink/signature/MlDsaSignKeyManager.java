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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code MlDsaPrivateKey} keys and produces new instances of {@code
 * MlDsaSignConscrypt}.
 */
/* Placeholder for internally public; DO NOT CHANGE. */ final class MlDsaSignKeyManager {
  // TODO(b/458349867): make OSS-public once ML-DSA is available in OSS Conscrypt (or we get the
  //  implementation elsewhere).

  static String getPublicKeyType() {
    return "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";
  }

  static String getPrivateKeyType() {
    return "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  }

  static final String ML_DSA_65_ALGORITHM = "ML-DSA-65";

  private static final KeyCreator<MlDsaParameters> KEY_CREATOR = MlDsaSignKeyManager::createKey;
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @AccessesPartialKey
  private static MlDsaPrivateKey createKey(
      MlDsaParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ML_DSA_65_ALGORITHM, provider);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    KeyFactory keyFactory = KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider);

    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setSerializedPublicKey(
                Bytes.copyFrom(
                    keyFactory
                        .getKeySpec(keyPair.getPublic(), MlDsaVerifyConscrypt.RawKeySpec.class)
                        .getEncoded()))
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .build();
    SecretBytes privateSeed =
        SecretBytes.copyFrom(
            keyFactory
                .getKeySpec(keyPair.getPrivate(), MlDsaVerifyConscrypt.RawKeySpec.class)
                .getEncoded(),
            InsecureSecretKeyAccess.get());

    return MlDsaPrivateKey.createWithoutVerification(publicKey, privateSeed);
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    return Map.of(
        "ML_DSA_65",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK),
        "ML_DSA_65_RAW",
        MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX));
  }

  /**
   * Registers the {@link MlDsaProtoSerialization}, named parameters, and the key (pair) creator.
   */
  public static void registerPair() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    if (ConscryptUtil.providerOrNull() == null) {
      throw new GeneralSecurityException("Cannot use ML-DSA without Conscrypt provider");
    }
    MlDsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, MlDsaParameters.class);
  }

  private MlDsaSignKeyManager() {}
}
