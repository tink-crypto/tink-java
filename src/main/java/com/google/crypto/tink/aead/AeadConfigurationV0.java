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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.aead.subtle.AesCtrHmacAead;
import com.google.crypto.tink.aead.subtle.AesEaxAead;
import com.google.crypto.tink.aead.subtle.AesGcmAead;
import com.google.crypto.tink.aead.subtle.AesGcmSivAead;
import com.google.crypto.tink.aead.subtle.ChaCha20Poly1305Aead;
import com.google.crypto.tink.aead.subtle.XAesGcmAead;
import com.google.crypto.tink.aead.subtle.XChaCha20Poly1305Aead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import java.security.GeneralSecurityException;

/**
 * AeadConfigurationV0 contains the following algorithms for Aead:
 *
 * <ul>
 *   <li>AesCtrHmac
 *   <li>AesGcm
 *   <li>AesGcmSiv
 *   <li>AesEax
 *   <li>ChaCha20Poly1305
 *   <li>XChaCha20Poly1305
 *   <li>XAesGcm
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class AeadConfigurationV0 {
  private AeadConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant AeadConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The AeadConfigurationV0 is the same as the AeadConfig, but if a key has been parsed
    // as a LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding
    // algorithm was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(AeadConfig2026.get())
        .addPrimitiveConstructor(
            AeadConfigurationV0::createAeadFromLegacyProtoKey, LegacyProtoKey.class, Aead.class)
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
  private static Aead createAeadFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof AesCtrHmacAeadKey) {
      return AesCtrHmacAead.create((AesCtrHmacAeadKey) reparsedKey);
    }
    if (reparsedKey instanceof AesGcmKey) {
      return AesGcmAead.create((AesGcmKey) reparsedKey);
    }
    if (reparsedKey instanceof AesGcmSivKey) {
      return AesGcmSivAead.create((AesGcmSivKey) reparsedKey);
    }
    if (reparsedKey instanceof AesEaxKey) {
      return AesEaxAead.create((AesEaxKey) reparsedKey);
    }
    if (reparsedKey instanceof ChaCha20Poly1305Key) {
      return ChaCha20Poly1305Aead.create((ChaCha20Poly1305Key) reparsedKey);
    }
    if (reparsedKey instanceof XChaCha20Poly1305Key) {
      return XChaCha20Poly1305Aead.create((XChaCha20Poly1305Key) reparsedKey);
    }
    if (reparsedKey instanceof XAesGcmKey) {
      return XAesGcmAead.create((XAesGcmKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }
}
