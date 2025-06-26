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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.subtle.PrfMac;
import java.security.GeneralSecurityException;

/**
 * MacConfigurationV1 contains the following primitives and algorithms for MAC and ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class MacConfigurationV1 {
  private MacConfigurationV1() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register Mac wrappers and concrete primitives.
      MacWrapper.registerToInternalPrimitiveRegistry(builder);
      ChunkedMacWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              MacConfigurationV1::createAesCmac, AesCmacKey.class, Mac.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(PrfMac::create, HmacKey.class, Mac.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              MacConfigurationV1::createChunkedAesCmac, AesCmacKey.class, ChunkedMac.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant MacConfigurationV1 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }

  // We only allow 32-byte AesCmac keys.
  private static final int AES_CMAC_KEY_SIZE_BYTES = 32;

  private static ChunkedMac createChunkedAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return ChunkedAesCmacImpl.create(key);
  }

  private static Mac createAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return PrfMac.create(key);
  }
}
