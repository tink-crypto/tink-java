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
import com.google.crypto.tink.signature.internal.SlhDsaKeyCreator;
import com.google.crypto.tink.signature.internal.SlhDsaProtoSerialization;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * SlhDsaSignKeyManager hosts the {@code registerPair()} method. The method registers the {@link
 * SlhDsaProtoSerialization}, named parameters, and the key (pair) creator, enabling creation,
 * parsing, and serialization of SLH-DSA keys in KeysetHandles.
 */
public final class SlhDsaSignKeyManager {

  private static final KeyCreator<SlhDsaParameters> KEY_CREATOR = SlhDsaKeyCreator::createKey;
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  /*
   * 1. other `namedParameters()` methods do, and this one might too in the future
   * 2 .we do not depend on Guava
   */
  @SuppressWarnings({"CheckedExceptionNotThrown", "JdkImmutableCollections"})
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    return Map.of(
        "SLH_DSA_SHA2_128S",
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
   *        (currently "SLH_DSA_SHA2_128S" and "SLH_DSA_SHA2_128S_RAW" available)
   * </ul>
   *
   * Currently the key creation functionality will only work if the Conscrypt provider was
   * explicitly registered (even though this method will succeed regardless).
   *
   * @throws GeneralSecurityException if called in FIPS mode.
   */
  public static void registerPair() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use SLH-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    SlhDsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, SlhDsaParameters.class);
  }

  private SlhDsaSignKeyManager() {}
}
