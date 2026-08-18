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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.mac.subtle.HmacChunkedMac;
import com.google.crypto.tink.mac.subtle.HmacMac;
import java.security.GeneralSecurityException;

/**
 * MacConfigurationV0 contains the following primitives and algorithms for MAC and ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class MacConfigurationV0 {
  private MacConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant MacConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The MacConfigurationV0 is the same as the MacConfig, but if a key has been parsed
    // as a LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding
    // algorithm was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(MacConfig2026.get())
        .addPrimitiveConstructor(
            MacConfigurationV0::createMacFromLegacyProtoKey, LegacyProtoKey.class, Mac.class)
        .addPrimitiveConstructor(
            MacConfigurationV0::createChunkedMacFromLegacyProtoKey,
            LegacyProtoKey.class,
            ChunkedMac.class)
        .build();
  }

  @LowLevelCryptoCaller
  private static Mac createMacFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey =
        MutableSerializationRegistry.globalInstance()
            .parseKey(
                key.getSerialization(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    if (reparsedKey instanceof AesCmacKey) {
      return MacConfig2026.createAesCmac((AesCmacKey) reparsedKey);
    }
    if (reparsedKey instanceof HmacKey) {
      return HmacMac.create((HmacKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }

  @LowLevelCryptoCaller
  private static ChunkedMac createChunkedMacFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey =
        MutableSerializationRegistry.globalInstance()
            .parseKey(
                key.getSerialization(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    if (reparsedKey instanceof AesCmacKey) {
      return MacConfig2026.createChunkedAesCmac((AesCmacKey) reparsedKey);
    }
    if (reparsedKey instanceof HmacKey) {
      return HmacChunkedMac.create((HmacKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }
}
