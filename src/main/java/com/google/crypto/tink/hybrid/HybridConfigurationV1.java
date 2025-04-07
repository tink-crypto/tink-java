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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import java.security.GeneralSecurityException;

/**
 * HybridConfigurationV1 contains the following algorithms for HybridEncrypt/HybridDecrypt:
 *
 * <ul>
 *   <li>EciesAeadHkdf
 *   <li>Hpke
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class HybridConfigurationV1 {
  private HybridConfigurationV1() {}

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

      // Register HybridDecrypt wrapper and concrete primitives.
      HybridDecryptWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EciesAeadHkdfHybridDecrypt::create, EciesPrivateKey.class, HybridDecrypt.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              HpkeDecrypt::create, HpkePrivateKey.class, HybridDecrypt.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Returns an instance of the {@code HybridConfigurationV1}.
   */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant HybridConfigurationV1 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }
}
