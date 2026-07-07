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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.subtle.AesSiv;
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
public class DeterministicAeadConfig2026 {
  private DeterministicAeadConfig2026() {}

  private static final DeterministicAeadWrapper DETERMINISTIC_AEAD_WRAPPER =
      new DeterministicAeadWrapper();
  private static final Configuration CONFIGURATION = create();
  private static final ProtoKeySerializer SERIALIZER = createProtoKeySerializer();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant DeterministicAeadConfig2026 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(DeterministicAead.class)) {
          return clazz.cast(
              DETERMINISTIC_AEAD_WRAPPER.wrap(
                  keysetHandle, DeterministicAeadConfig2026::createDeterministicAead));
        }
        throw new GeneralSecurityException(
            "DeterministicAeadConfig2026 can only create DeterministicAead primitive");
      }

      @Override
      @AccessesPartialKey
      public Key createKey(Parameters parameters, @Nullable Integer idRequirement)
          throws GeneralSecurityException {
        if (parameters instanceof AesSivParameters) {
          AesSivParameters aesSivParameters = (AesSivParameters) parameters;
          return AesSivKey.builder()
              .setParameters(aesSivParameters)
              .setKeyBytes(SecretBytes.randomBytes(aesSivParameters.getKeySizeBytes()))
              .setIdRequirement(idRequirement)
              .build();
        }
        throw new GeneralSecurityException(
            "Unrecognized parameters for DeterministicAeadConfig2026: " + parameters);
      }

      @Override
      public <P> P getOrNull(Class<P> clazz) {
        if (clazz.equals(ProtoKeySerializer.class)) {
          return clazz.cast(SERIALIZER);
        }
        return null;
      }
    };
  }

  private static DeterministicAead createDeterministicAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesSivKey) {
      return createAesSiv((AesSivKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  // We only allow 64-byte keys for AesSiv, because 32-byte keys might not provide 128-bit security
  // level in multi-user setting.
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

  private static ProtoKeySerializer createProtoKeySerializer() {
    try {
      SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
      AesSivProtoSerialization.register(builder);
      return builder.build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
