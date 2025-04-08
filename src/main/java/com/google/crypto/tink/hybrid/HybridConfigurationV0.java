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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
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

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register HybridEncrypt wrapper and concrete primitives.
      HybridEncryptWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EciesAeadHkdfHybridEncrypt::create, EciesPublicKey.class, HybridEncrypt.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              HpkeEncrypt::create, HpkePublicKey.class, HybridEncrypt.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              HybridConfigurationV0::createHybridEncryptFromLegacyProtoKey,
              LegacyProtoKey.class,
              HybridEncrypt.class));

      // Register HybridDecrypt wrapper and concrete primitives.
      HybridDecryptWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EciesAeadHkdfHybridDecrypt::create, EciesPrivateKey.class, HybridDecrypt.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              HpkeDecrypt::create, HpkePrivateKey.class, HybridDecrypt.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              HybridConfigurationV0::createHybridDecryptFromLegacyProtoKey,
              LegacyProtoKey.class,
              HybridDecrypt.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HybridEncrypt createHybridEncryptFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key parsedKey;
    try {
      parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException("Failed to re-parse LegacyProtoKey for HybridEncrypt", e);
    }
    if (parsedKey instanceof EciesPublicKey) {
      return EciesAeadHkdfHybridEncrypt.create((EciesPublicKey) parsedKey);
    }
    if (parsedKey instanceof HpkePublicKey) {
      return HpkeEncrypt.create((HpkePublicKey) parsedKey);
    }
    throw new GeneralSecurityException(
        "Failed to re-parse LegacyProtoKey for HybridEncrypt: the parsed key type is"
            + parsedKey.getClass().getName()
            + ", expected .");
  }

  private static HybridDecrypt createHybridDecryptFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key parsedKey;
    try {
      parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException("Failed to re-parse LegacyProtoKey for HybridDecrypt", e);
    }
    if (parsedKey instanceof EciesPrivateKey) {
      return EciesAeadHkdfHybridDecrypt.create((EciesPrivateKey) parsedKey);
    }
    if (parsedKey instanceof HpkePrivateKey) {
      return HpkeDecrypt.create((HpkePrivateKey) parsedKey);
    }
    throw new GeneralSecurityException(
        "Failed to re-parse LegacyProtoKey for HybridDecrypt: the parsed key type is"
            + parsedKey.getClass().getName()
            + ", expected .");
  }

  /** Returns an instance of the {@code HybridConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant HybridConfigurationV0 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }
}
