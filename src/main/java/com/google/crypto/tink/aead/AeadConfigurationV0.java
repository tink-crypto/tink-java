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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.XAesGcm;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
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
 *   <li>XAesGcm
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
              AeadConfigurationV0::createChaCha20Poly1305, ChaCha20Poly1305Key.class, Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AeadConfigurationV0::createXChaCha20Poly1305,
              XChaCha20Poly1305Key.class,
              Aead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(XAesGcm::create, XAesGcmKey.class, Aead.class));
      // This does not include XAesGcm since we don't expect the users of XAesGcm to use the legacy
      // API.
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AeadConfigurationV0::createAeadFromLegacyProtoKey, LegacyProtoKey.class, Aead.class));

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

  private static Aead createAeadFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    try {
      Key parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      if (parsedKey instanceof AesCtrHmacAeadKey) {
        return EncryptThenAuthenticate.create((AesCtrHmacAeadKey) parsedKey);
      }
      if (parsedKey instanceof AesEaxKey) {
        return AesEaxJce.create((AesEaxKey) parsedKey);
      }
      if (parsedKey instanceof AesGcmKey) {
        return AesGcmJce.create((AesGcmKey) parsedKey);
      }
      if (parsedKey instanceof AesGcmSivKey) {
        return AesGcmSiv.create((AesGcmSivKey) parsedKey);
      }
      if (parsedKey instanceof ChaCha20Poly1305Key) {
        return createChaCha20Poly1305((ChaCha20Poly1305Key) parsedKey);
      }
      if (parsedKey instanceof XChaCha20Poly1305Key) {
        return createXChaCha20Poly1305((XChaCha20Poly1305Key) parsedKey);
      }
      throw new GeneralSecurityException(
          "Failed to re-parse LegacyProtoKey for Aead: the parsed key type is"
              + parsedKey.getClass().getName()
              + ", expected one of: AesCtrHmacKey, AesEaxKey, AesGcmKey, AesGcmSivKey,"
              + " ChaCha20Poly1305Key, XChaCha20Poly1305Key.");
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException("Failed to re-parse LegacyProtoKey for Aead", e);
    }
  }
}
