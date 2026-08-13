// Copyright 2025 Google LLC
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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.mac.internal.WrappedChunkedMac;
import com.google.crypto.tink.mac.internal.WrappedMac;
import com.google.crypto.tink.mac.subtle.AesCmacChunkedMac;
import com.google.crypto.tink.mac.subtle.AesCmacMac;
import com.google.crypto.tink.mac.subtle.AesCmacProtoSerialization;
import com.google.crypto.tink.mac.subtle.HmacChunkedMac;
import com.google.crypto.tink.mac.subtle.HmacMac;
import com.google.crypto.tink.mac.subtle.HmacProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * MacConfig2026 contains the following primitives and algorithms for MAC and ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 */
public final class MacConfig2026 {
  private MacConfig2026() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    return CONFIGURATION;
  }

  private static final String AES_CMAC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCmacKey";
  private static final String HMAC_TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
        .addPrimitiveWrapper(ChunkedMac.class, ChunkedMac.class, WrappedChunkedMac::create)
        // AesCmac
        .addKeyCreator(AesCmacParameters.class, MacConfig2026::createAesCmacKey)
        .addPrimitiveConstructor(MacConfig2026::createAesCmac, AesCmacKey.class, Mac.class)
        .addPrimitiveConstructor(
            MacConfig2026::createChunkedAesCmac, AesCmacKey.class, ChunkedMac.class)
        .addKeySerializer(AesCmacKey.class, AesCmacProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesCmacParameters.class, AesCmacProtoSerialization::serializeParameters)
        .addKeyParser(AES_CMAC_TYPE_URL, AesCmacProtoSerialization::parseKey)
        .addParametersParser(AES_CMAC_TYPE_URL, AesCmacProtoSerialization::parseParameters)
        // Hmac
        .addKeyCreator(HmacParameters.class, MacConfig2026::createHmacKey)
        .addPrimitiveConstructor(HmacMac::create, HmacKey.class, Mac.class)
        .addPrimitiveConstructor(HmacChunkedMac::create, HmacKey.class, ChunkedMac.class)
        .addKeySerializer(HmacKey.class, HmacProtoSerialization::serializeKey)
        .addParametersSerializer(HmacParameters.class, HmacProtoSerialization::serializeParameters)
        .addKeyParser(HMAC_TYPE_URL, HmacProtoSerialization::parseKey)
        .addParametersParser(HMAC_TYPE_URL, HmacProtoSerialization::parseParameters)
        .build();
  }

  @AccessesPartialKey
  private static AesCmacKey createAesCmacKey(
      AesCmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException("Cannot create new AesCmacKey in FIPS mode");
    }
    return AesCmacKey.builder()
        .setParameters(parameters)
        .setAesKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @AccessesPartialKey
  private static HmacKey createHmacKey(HmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      throw new GeneralSecurityException("Cannot create HmacKey in FIPS mode without FIPS module");
    }
    return HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  // We only allow 32-byte AesCmac keys.
  private static final int AES_CMAC_KEY_SIZE_BYTES = 32;

  @LowLevelCryptoCaller
  private static ChunkedMac createChunkedAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return AesCmacChunkedMac.create(key);
  }

  @LowLevelCryptoCaller
  private static Mac createAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return AesCmacMac.create(key);
  }
}
