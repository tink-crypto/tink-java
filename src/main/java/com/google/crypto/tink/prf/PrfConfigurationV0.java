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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.prf.subtle.AesCmacPrf;
import com.google.crypto.tink.prf.subtle.HkdfPrf;
import com.google.crypto.tink.prf.subtle.HmacPrf;
import java.security.GeneralSecurityException;

/**
 * PrfConfigurationV0 contains the following algorithms for PrfSet:
 *
 * <ul>
 *   <li>HmacPrf
 *   <li>HkdfPrf
 *   <li>AesCmacPrf
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class PrfConfigurationV0 {
  private PrfConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns an instance of the {@code PrfConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant PrfConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The PrfConfigurationV0 is the same as the PrfConfig, but if a key has been parsed as a
    // LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding algorithm
    // was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(PrfConfig2026.get())
        .addPrimitiveConstructor(
            PrfConfigurationV0::createPrfFromLegacyProtoKey,
            LegacyProtoKey.class,
            Prf.class)
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

  // We use a somewhat larger minimum key size than usual, because PRFs might be used by many users,
  // in which case the security can degrade by a factor depending on the number of users. (Discussed
  // for example in https://eprint.iacr.org/2012/159)
  private static final int MIN_HKDF_PRF_KEY_SIZE = 32;

  @LowLevelCryptoCaller
  private static Prf createPrfFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof HmacPrfKey) {
      return HmacPrf.create((HmacPrfKey) reparsedKey);
    }
    if (reparsedKey instanceof HkdfPrfKey) {
      return createHkdfPrf((HkdfPrfKey) reparsedKey);
    }
    if (reparsedKey instanceof AesCmacPrfKey) {
      return createAesCmacPrf((AesCmacPrfKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }

  @LowLevelCryptoCaller
  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() < MIN_HKDF_PRF_KEY_SIZE) {
      throw new GeneralSecurityException(
          "HkdfPrf key size must be at least " + MIN_HKDF_PRF_KEY_SIZE);
    }
    if (key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA256
        && key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("HkdfPrf hash type must be SHA256 or SHA512");
    }
    return HkdfPrf.create(key);
  }

  @LowLevelCryptoCaller
  private static Prf createAesCmacPrf(AesCmacPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != 32) {
      throw new GeneralSecurityException("AesCmacPrf key size must be 32 bytes");
    }
    return AesCmacPrf.create(key);
  }
}
