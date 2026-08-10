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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.prf.internal.WrappedPrfSet;
import com.google.crypto.tink.prf.subtle.AesCmacPrf;
import com.google.crypto.tink.prf.subtle.AesCmacPrfProtoSerialization;
import com.google.crypto.tink.prf.subtle.HkdfPrf;
import com.google.crypto.tink.prf.subtle.HkdfPrfProtoSerialization;
import com.google.crypto.tink.prf.subtle.HmacPrf;
import com.google.crypto.tink.prf.subtle.HmacPrfProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * PrfConfig2026 contains the following primitives and algorithms for {@link PrfSet}:
 *
 * <ul>
 *   <li>HmacPrf
 *   <li>HkdfPrf
 *   <li>AesCmacPrf
 * </ul>
 */
public class PrfConfig2026 {
  private PrfConfig2026() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    return CONFIGURATION;
  }

  private static final String HMAC_PRF_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HmacPrfKey";
  private static final String HKDF_PRF_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HkdfPrfKey";
  private static final String AES_CMAC_PRF_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

  private static final int MIN_HKDF_PRF_KEY_SIZE = 32;

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(PrfSet.class, Prf.class, WrappedPrfSet::create)
        // HmacPrf
        .addKeyCreator(HmacPrfParameters.class, PrfConfig2026::createHmacPrfKey)
        .addPrimitiveConstructor(HmacPrf::create, HmacPrfKey.class, Prf.class)
        .addKeySerializer(HmacPrfKey.class, HmacPrfProtoSerialization::serializeKey)
        .addParametersSerializer(
            HmacPrfParameters.class, HmacPrfProtoSerialization::serializeParameters)
        .addKeyParser(HMAC_PRF_TYPE_URL, HmacPrfProtoSerialization::parseKey)
        .addParametersParser(HMAC_PRF_TYPE_URL, HmacPrfProtoSerialization::parseParameters)
        // HkdfPrf
        .addKeyCreator(HkdfPrfParameters.class, PrfConfig2026::createHkdfPrfKey)
        .addPrimitiveConstructor(PrfConfig2026::createHkdfPrf, HkdfPrfKey.class, Prf.class)
        .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
        .addParametersSerializer(
            HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
        .addKeyParser(HKDF_PRF_TYPE_URL, HkdfPrfProtoSerialization::parseKey)
        .addParametersParser(HKDF_PRF_TYPE_URL, HkdfPrfProtoSerialization::parseParameters)
        // AesCmacPrf
        .addKeyCreator(AesCmacPrfParameters.class, PrfConfig2026::createAesCmacPrfKey)
        .addPrimitiveConstructor(PrfConfig2026::createAesCmacPrf, AesCmacPrfKey.class, Prf.class)
        .addKeySerializer(AesCmacPrfKey.class, AesCmacPrfProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesCmacPrfParameters.class, AesCmacPrfProtoSerialization::serializeParameters)
        .addKeyParser(AES_CMAC_PRF_TYPE_URL, AesCmacPrfProtoSerialization::parseKey)
        .addParametersParser(AES_CMAC_PRF_TYPE_URL, AesCmacPrfProtoSerialization::parseParameters)
        .build();
  }

  @LowLevelCryptoCaller
  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException("Cannot use HkdfPrf in FIPS mode");
    }
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

  @AccessesPartialKey
  private static HmacPrfKey createHmacPrfKey(
      HmacPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("PRF Keys are not expected to have an id Requirement");
    }
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      throw new GeneralSecurityException(
          "Cannot create HmacPrfKey in FIPS mode without FIPS module");
    }
    return HmacPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @AccessesPartialKey
  private static HkdfPrfKey createHkdfPrfKey(
      HkdfPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("PRF Keys are not expected to have an id Requirement");
    }
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException("Cannot create new HkdfPrfKey in FIPS mode");
    }
    return HkdfPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @AccessesPartialKey
  private static AesCmacPrfKey createAesCmacPrfKey(
      AesCmacPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("PRF Keys are not expected to have an id Requirement");
    }
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException("Cannot create new AesCmacPrfKey in FIPS mode");
    }
    return AesCmacPrfKey.create(parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }
}
