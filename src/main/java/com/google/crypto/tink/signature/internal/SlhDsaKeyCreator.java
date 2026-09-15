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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaPrivateKey;
import com.google.crypto.tink.signature.SlhDsaPublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import javax.annotation.Nullable;

/** Creates SLH-DSA keys. */
public final class SlhDsaKeyCreator {
  private static final String SLH_DSA_SHA2_128S_ALGORITHM = "SLH-DSA-SHA2-128S";

  @AccessesPartialKey
  public static SlhDsaPrivateKey createKey(
      SlhDsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException("Cannot create new MlDsaPrivateKeys in FIPS mode");
    }
    if (parameters.getPrivateKeySize() != SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES
        || parameters.getHashType() != SlhDsaParameters.HashType.SHA2
        || parameters.getSignatureType() != SlhDsaParameters.SignatureType.SMALL_SIGNATURE) {
      throw new GeneralSecurityException("Unsupported SLH-DSA parameters");
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }

    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance(SLH_DSA_SHA2_128S_ALGORITHM, provider);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    KeyFactory keyFactory = KeyFactory.getInstance(SLH_DSA_SHA2_128S_ALGORITHM, provider);

    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setSerializedPublicKey(
                Bytes.copyFrom(
                    keyFactory
                        .getKeySpec(keyPair.getPublic(), SlhDsaVerifyConscrypt.RawKeySpec.class)
                        .getEncoded()))
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .build();
    SecretBytes privateKeyBytes =
        SecretBytes.copyFrom(
            keyFactory
                .getKeySpec(keyPair.getPrivate(), SlhDsaVerifyConscrypt.RawKeySpec.class)
                .getEncoded(),
            InsecureSecretKeyAccess.get());

    return SlhDsaPrivateKey.createWithoutVerification(publicKey, privateKeyBytes);
  }

  private SlhDsaKeyCreator() {}
}
