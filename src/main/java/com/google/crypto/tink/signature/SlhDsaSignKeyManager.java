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
import com.google.crypto.tink.signature.internal.SlhDsaProtoSerialization;
import com.google.crypto.tink.signature.internal.SlhDsaVerifyConscrypt;
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
 * SlhDsaSignKeyManager hosts the {@code registerPair()} method. The method registers the {@link
 * SlhDsaProtoSerialization}, named parameters, and the key (pair) creator, enabling creation,
 * parsing, and serialization of SLH-DSA keys in KeysetHandles.
 */
public final class SlhDsaSignKeyManager {
  static final String SLH_DSA_SHA2_128S_ALGORITHM = "SLH-DSA-SHA2-128S";

  private static final KeyCreator<SlhDsaParameters> KEY_CREATOR = SlhDsaSignKeyManager::createKey;
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @AccessesPartialKey
  private static SlhDsaPrivateKey createKey(
      SlhDsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
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

  /*
   * 1. other `namedParameters()` methods do, and this one might too in the future
   * 2 .we do not depend on Guava
   */
  @SuppressWarnings({"CheckedExceptionNotThrown", "JdkImmutableCollections"})
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    return Map.of(
        "SLH_DSA_SHA2_128S_TINK",
        SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.TINK),
        "SLH_DSA_SHA2_128S_RAW",
        SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.NO_PREFIX));
  }

  /**
   * Registers the {@link SlhDsaProtoSerialization}, named parameters, and the key (pair) creator,
   * for now only supporting SLH-DSA-SHA2-128S in TINK and NO_PREFIX veriants. This enables:
   * <ul>
   *   <li> parsing and serializing SLH-DSA keys with {@code TinkProtoKeysetFormat}
   *   <li> creation of new SLH-DSA keys with {@code KeysetHandle#generateEntryFromParameters}
   *   <li> creation of new SLH-DSA keys with {@code KeysetHandle#generateEntryFromParametersName}
   *        (currently "SLH_DSA_SHA2_128S_TINK" and "SLH_DSA_SHA2_128S_RAW" available)
   * </ul>
   */
  public static void registerPair() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use SLH-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    if (ConscryptUtil.providerOrNull() == null) {
      throw new GeneralSecurityException("Cannot use SLH-DSA without Conscrypt provider");
    }
    SlhDsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, SlhDsaParameters.class);
  }

  private SlhDsaSignKeyManager() {}
}
