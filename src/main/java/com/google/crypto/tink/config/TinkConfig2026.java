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

package com.google.crypto.tink.config;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.aead.AeadConfig2026;
import com.google.crypto.tink.daead.DeterministicAeadConfig2026;
import com.google.crypto.tink.hybrid.HybridConfig2026;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.jwt.JwtConfig2026;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig2026;
import com.google.crypto.tink.mac.MacConfig2026;
import com.google.crypto.tink.prf.PrfConfig2026;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig2026;

/**
 * TinkConfig2026 contains the configuration for all primitives and algorithms in Tink for 2026.
 *
 * <p>It contains:
 *
 * <ul>
 *   <li>{@link AeadConfig2026}
 *   <li>{@link DeterministicAeadConfig2026}
 *   <li>{@link HybridConfig2026}
 *   <li>{@link JwtConfig2026}
 *   <li>{@link KeyDerivationConfig2026}
 *   <li>{@link MacConfig2026}
 *   <li>{@link PrfConfig2026}
 *   <li>{@link SignatureConfig2026}
 *   <li>{@link StreamingAeadConfig2026}
 * </ul>
 */
public final class TinkConfig2026 {
  private TinkConfig2026() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(AeadConfig2026.get())
        .mergeProtoBasedConfiguration(DeterministicAeadConfig2026.get())
        .mergeProtoBasedConfiguration(HybridConfig2026.get())
        .mergeProtoBasedConfiguration(JwtConfig2026.get())
        .mergeProtoBasedConfiguration(KeyDerivationConfig2026.get())
        .mergeProtoBasedConfiguration(MacConfig2026.get())
        .mergeProtoBasedConfiguration(PrfConfig2026.get())
        .mergeProtoBasedConfiguration(SignatureConfig2026.get())
        .mergeProtoBasedConfiguration(StreamingAeadConfig2026.get())
        .build();
  }
}
