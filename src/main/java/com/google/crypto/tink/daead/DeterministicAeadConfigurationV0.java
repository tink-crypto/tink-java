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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.AesSiv;
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

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register DeterministicAead wrapper and concrete primitives.
      DeterministicAeadWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              DeterministicAeadConfigurationV0::createAesSiv,
              AesSivKey.class,
              DeterministicAead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              DeterministicAeadConfigurationV0::createDeterministicAeadFromLegacyProtoKey,
              LegacyProtoKey.class,
              DeterministicAead.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant DeterministicAeadConfigurationV0 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }

  // We only allow 64-byte keys for AesSiv.
  private static final int KEY_SIZE_IN_BYTES = 64;

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
    return AesSiv.create(key);
  }

  private static DeterministicAead createDeterministicAeadFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key parsedKey;
    try {
      parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      if (parsedKey instanceof AesSivKey) {
        return createAesSiv((AesSivKey) parsedKey);
      }
      throw new GeneralSecurityException(
          "Failed to re-parse LegacyProtoKey for DeterministicAead: the parsed key type is"
              + parsedKey.getClass().getName()
              + ", expected AesSivKey.");
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(
          "Failed to re-parse LegacyProtoKey for DeterministicAead", e);
    }
  }
}
