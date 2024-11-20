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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import java.security.GeneralSecurityException;

/**
 * AeadConfigurationV0 contains the following algorithms for Aead:
 *
 * <ul>
 *   <li>AesCtrHmac
 *   <li>AesGcm
 *   <li>AesGcmSiv
 *   <li>AesEax
 *   <li>ChaCha20Poly1305
 *   <li>XChaCha20Poly1305
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class AeadConfigurationV0 {
  private AeadConfigurationV0() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register {@code Aead} wrapper and concrete primitives.
      AeadWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EncryptThenAuthenticate::create, AesCtrHmacAeadKey.class, Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(AesGcmJce::create, AesGcmKey.class, Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(AesGcmSiv::create, AesGcmSivKey.class, Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(AesEaxJce::create, AesEaxKey.class, Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AeadConfigurationV0::createChaCha20Poly1305,
              ChaCha20Poly1305Key.class,
              Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AeadConfigurationV0::createXChaCha20Poly1305,
              XChaCha20Poly1305Key.class,
              Aead.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Returns an instance of the {@code AeadConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant AeadConfigurationV0 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }

  private static Aead createChaCha20Poly1305(ChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (ChaCha20Poly1305Jce.isSupported()) {
      return ChaCha20Poly1305Jce.create(key);
    }
    return ChaCha20Poly1305.create(key);
  }

  private static Aead createXChaCha20Poly1305(XChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (XChaCha20Poly1305Jce.isSupported()) {
      return XChaCha20Poly1305Jce.create(key);
    }
    return XChaCha20Poly1305.create(key);
  }
}
