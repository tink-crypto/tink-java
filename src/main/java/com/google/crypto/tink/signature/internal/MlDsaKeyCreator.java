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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import javax.annotation.Nullable;

/** Creates ML-DSA keys. */
public final class MlDsaKeyCreator {

  private static final String ML_DSA_44_ALGORITHM = "ML-DSA-44";
  private static final String ML_DSA_65_ALGORITHM = "ML-DSA-65";
  private static final String ML_DSA_87_ALGORITHM = "ML-DSA-87";

  @AccessesPartialKey
  public static MlDsaPrivateKey createKey(
      MlDsaParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    KeyPairGenerator keyPairGenerator;
    KeyFactory keyFactory;
    if (parameters.getMlDsaInstance() == MlDsaInstance.ML_DSA_44) {
      keyPairGenerator = KeyPairGenerator.getInstance(ML_DSA_44_ALGORITHM, provider);
      keyFactory = KeyFactory.getInstance(ML_DSA_44_ALGORITHM, provider);
    } else if (parameters.getMlDsaInstance() == MlDsaInstance.ML_DSA_65) {
      keyPairGenerator = KeyPairGenerator.getInstance(ML_DSA_65_ALGORITHM, provider);
      keyFactory = KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider);
    } else if (parameters.getMlDsaInstance() == MlDsaInstance.ML_DSA_87) {
      keyPairGenerator = KeyPairGenerator.getInstance(ML_DSA_87_ALGORITHM, provider);
      keyFactory = KeyFactory.getInstance(ML_DSA_87_ALGORITHM, provider);
    } else {
      throw new GeneralSecurityException(
          "Unknown ML-DSA instance: " + parameters.getMlDsaInstance());
    }
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

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

  private MlDsaKeyCreator() {}
}
