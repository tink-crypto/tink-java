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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.streamingaead.subtle.AesCtrHmacStreamingAead;
import com.google.crypto.tink.streamingaead.subtle.AesGcmHkdfStreamingAead;
import java.security.GeneralSecurityException;

/**
 * StreamingAeadConfigurationV0 contains the following algorithms for StreamingAEAD:
 *
 * <ul>
 *   <li>AesGcmHkdfStreaming
 *   <li>AesCtrHmacStreaming
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class StreamingAeadConfigurationV0 {
  private StreamingAeadConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant StreamingAeadConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The StreamingAeadConfigurationV0 is the same as the StreamingAeadConfig, but if a key has been parsed
    // as a LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding
    // algorithm was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(StreamingAeadConfig2026.get())
        .addPrimitiveConstructor(
            StreamingAeadConfigurationV0::createStreamingAeadFromLegacyProtoKey,
            LegacyProtoKey.class,
            StreamingAead.class)
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
  private static StreamingAead createStreamingAeadFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof AesGcmHkdfStreamingKey) {
      return AesGcmHkdfStreamingAead.create((AesGcmHkdfStreamingKey) reparsedKey);
    }
    if (reparsedKey instanceof AesCtrHmacStreamingKey) {
      return AesCtrHmacStreamingAead.create((AesCtrHmacStreamingKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }
}
