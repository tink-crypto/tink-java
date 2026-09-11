// Copyright 2024 Google LLC
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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.subtle.AesSivDeterministicAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/**
 * DeterministicAeadConfigurationV0 contains the following algorithms for DeterministicAEAD:
 *
 * <ul>
 *   <li>AesSiv
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class DeterministicAeadConfigurationV0 {
  private DeterministicAeadConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant DeterministicAeadConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The DeterministicAeadConfigurationV0 is the same as the DeterministicAeadConfig, but if a key
    // has been parsed as a LegacyProtoKey (which happens if we use the RegistryConfig and the
    // corresponding algorithm was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(DeterministicAeadConfig2026.get())
        .addPrimitiveConstructor(
            DeterministicAeadConfigurationV0::createDeterministicAeadFromLegacyProtoKey,
            LegacyProtoKey.class,
            DeterministicAead.class)
        .build();
  }

  @LowLevelCryptoCaller
  private static Key reparseKey(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerializer protoKeySerializer = get().getOrNull(ProtoKeySerializer.class);
    if (protoKeySerializer == null) {
      throw new GeneralSecurityException(
          "Unexpected: CONFIGURATION does not support Proto Serialization");
    }
    return protoKeySerializer.parseKey(
        key.getSerialization(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
  }

  // We only allow 64-byte keys for AesSiv, because 32-byte keys might not provide 128-bit security
  // level in multi-user setting.
  private static final int KEY_SIZE_IN_BYTES = 64;

  @LowLevelCryptoCaller
  private static DeterministicAead createDeterministicAeadFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof AesSivKey) {
      return createAesSiv((AesSivKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }

  @LowLevelCryptoCaller
  private static DeterministicAead createAesSiv(AesSivKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "invalid key size: "
              + key.getParameters().getKeySizeBytes()
              + ". Valid keys must have "
              + KEY_SIZE_IN_BYTES
              + " bytes.");
    }
    return AesSivDeterministicAead.create(key);
  }
}
