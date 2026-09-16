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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.subtle.EciesDecrypt;
import com.google.crypto.tink.hybrid.subtle.EciesEncrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeDecrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeEncrypt;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import java.security.GeneralSecurityException;

/**
 * HybridConfigurationV0 contains the following algorithms for HybridEncrypt/HybridDecrypt:
 *
 * <ul>
 *   <li>EciesAeadHkdf
 *   <li>Hpke
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class HybridConfigurationV0 {
  private HybridConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns an instance of the {@code HybridConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant HybridConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The HybridConfigurationV0 is the same as the HybridConfig, but if a key has been parsed as a
    // LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding algorithm
    // was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(HybridConfig2026.get())
        .addPrimitiveConstructor(
            HybridConfigurationV0::createHybridEncryptFromLegacyProtoKey,
            LegacyProtoKey.class,
            HybridEncrypt.class)
        .addPrimitiveConstructor(
            HybridConfigurationV0::createHybridDecryptFromLegacyProtoKey,
            LegacyProtoKey.class,
            HybridDecrypt.class)
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

  @LowLevelCryptoCaller
  private static HybridEncrypt createHybridEncryptFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof EciesPublicKey) {
      return EciesEncrypt.create((EciesPublicKey) reparsedKey);
    }
    if (reparsedKey instanceof HpkePublicKey) {
      return HpkeEncrypt.create((HpkePublicKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }

  @LowLevelCryptoCaller
  private static HybridDecrypt createHybridDecryptFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof EciesPrivateKey) {
      return EciesDecrypt.create((EciesPrivateKey) reparsedKey);
    }
    if (reparsedKey instanceof HpkePrivateKey) {
      return HpkeDecrypt.create((HpkePrivateKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }
}
