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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.internal.WrappedDeterministicAead;
import com.google.crypto.tink.daead.subtle.AesSivDeterministicAead;
import com.google.crypto.tink.daead.subtle.AesSivProtoSerialization;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import javax.annotation.Nullable;

/**
 * DeterministicAeadConfig2026 contains the following primitives and algorithms for
 * DeterministicAEAD:
 *
 * <ul>
 *   <li>AesSiv
 * </ul>
 */
public final class DeterministicAeadConfig2026 {
  private DeterministicAeadConfig2026() {}

  private static final Configuration CONFIGURATION = create();
  private static final Configuration EMPTY_CONFIGURATION =
      new ProtoBasedConfigurationBuilder().build();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    if (TinkFipsUtil.useOnlyFips()) {
      return EMPTY_CONFIGURATION;
    }
    return CONFIGURATION;
  }

  private static final String AES_SIV_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesSivKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(
            DeterministicAead.class,
            DeterministicAead.class,
            WrappedDeterministicAead::create)
        .addKeyCreator(AesSivParameters.class, DeterministicAeadConfig2026::createAesSivKey)
        .addPrimitiveConstructor(
            DeterministicAeadConfig2026::createAesSivPrimitive,
            AesSivKey.class,
            DeterministicAead.class)
        .addKeySerializer(AesSivKey.class, AesSivProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesSivParameters.class, AesSivProtoSerialization::serializeParameters)
        .addKeyParser(AES_SIV_TYPE_URL, AesSivProtoSerialization::parseKey)
        .addParametersParser(AES_SIV_TYPE_URL, AesSivProtoSerialization::parseParameters)
        .build();
  }

  @AccessesPartialKey
  private static AesSivKey createAesSivKey(
      AesSivParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return AesSivKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  // We only allow 64-byte keys for AesSiv, because 32-byte keys might not provide 128-bit security
  // level in multi-user setting.
  private static final int KEY_SIZE_IN_BYTES = 64;

  @LowLevelCryptoCaller
  private static DeterministicAead createAesSivPrimitive(AesSivKey key)
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
