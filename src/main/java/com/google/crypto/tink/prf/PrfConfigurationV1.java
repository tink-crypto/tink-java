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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import java.security.GeneralSecurityException;

/**
 * PrfConfigurationV1 contains the following algorithms for PrfSet:
 *
 * <ul>
 *   <li>HmacPrf
 *   <li>HkdfPrf
 *   <li>AesCmacPrf
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class PrfConfigurationV1 {
  private PrfConfigurationV1() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register {@code PrfSet} wrapper and concrete primitives.
      PrfSetWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(PrfHmacJce::create, HmacPrfKey.class, Prf.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              PrfConfigurationV1::createHkdfPrf, HkdfPrfKey.class, Prf.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              PrfConfigurationV1::createAesCmacPrf, AesCmacPrfKey.class, Prf.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Returns an instance of the {@code PrfConfigurationV1}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant PrfConfigurationV1 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }

  // We use a somewhat larger minimum key size than usual, because PRFs might be used by many users,
  // in which case the security can degrade by a factor depending on the number of users. (Discussed
  // for example in https://eprint.iacr.org/2012/159)
  private static final int MIN_HKDF_PRF_KEY_SIZE = 32;

  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() < MIN_HKDF_PRF_KEY_SIZE) {
      throw new GeneralSecurityException(
          "HkdfPrf key size must be at least " + MIN_HKDF_PRF_KEY_SIZE);
    }
    if (key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA256
        && key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("HkdfPrf hash type must be SHA256 or SHA512");
    }
    return PrfImpl.wrap(HkdfStreamingPrf.create(key));
  }

  private static Prf createAesCmacPrf(AesCmacPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != 32) {
      throw new GeneralSecurityException("AesCmacPrf key size must be 32 bytes");
    }
    return PrfAesCmac.create(key);
  }
}
