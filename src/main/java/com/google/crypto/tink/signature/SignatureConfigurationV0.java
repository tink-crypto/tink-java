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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import java.security.GeneralSecurityException;

/**
 * SignatureConfigurationV0 contains the following algorithms for PublicKeySign/Verify:
 *
 * <ul>
 *   <li>Ecdsa
 *   <li>RsaSsaPss
 *   <li>RsaSsaPkcs1
 *   <li>Ed25519
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class SignatureConfigurationV0 {
  private SignatureConfigurationV0() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register {@code PublicKeySign/Verify} wrappers and concrete primitives.
      PublicKeySignWrapper.registerToInternalPrimitiveRegistry(builder);
      PublicKeyVerifyWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EcdsaSignJce::create, EcdsaPrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              EcdsaVerifyJce::create, EcdsaPublicKey.class, PublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              RsaSsaPssSignJce::create, RsaSsaPssPrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              RsaSsaPssVerifyJce::create, RsaSsaPssPublicKey.class, PublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              RsaSsaPkcs1SignJce::create, RsaSsaPkcs1PrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              RsaSsaPkcs1VerifyJce::create, RsaSsaPkcs1PublicKey.class, PublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              Ed25519Sign::create, Ed25519PrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              Ed25519Verify::create, Ed25519PublicKey.class, PublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              SignatureConfigurationV0::createPublicKeySignFromLegacyProtoKey,
              LegacyProtoKey.class,
              PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              SignatureConfigurationV0::createPublicKeyVerifyFromLegacyProtoKey,
              LegacyProtoKey.class,
              PublicKeyVerify.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static PublicKeySign createPublicKeySignFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key parsedKey;
    try {
      parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException("Failed to re-parse LegacyProtoKey for PublicKeySign", e);
    }
    if (parsedKey instanceof EcdsaPrivateKey) {
      return EcdsaSignJce.create((EcdsaPrivateKey) parsedKey);
    }
    if (parsedKey instanceof Ed25519PrivateKey) {
      return Ed25519Sign.create((Ed25519PrivateKey) parsedKey);
    }
    if (parsedKey instanceof RsaSsaPkcs1PrivateKey) {
      return RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) parsedKey);
    }
    if (parsedKey instanceof RsaSsaPssPrivateKey) {
      return RsaSsaPssSignJce.create((RsaSsaPssPrivateKey) parsedKey);
    }
    throw new GeneralSecurityException(
        "Failed to re-parse LegacyProtoKey for PublicKeySign: the parsed key type is"
            + parsedKey.getClass().getName()
            + ", expected one of: EcdsaPrivateKey, Ed25519PrivateKey, RsaSsaPkcs1PrivateKey,"
            + " RsaSsaPssPrivateKey.");
  }

  private static PublicKeyVerify createPublicKeyVerifyFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key parsedKey;
    try {
      parsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  key.getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(
          "Failed to re-parse LegacyProtoKey for PublicKeyVerify", e);
    }
    if (parsedKey instanceof EcdsaPublicKey) {
      return EcdsaVerifyJce.create((EcdsaPublicKey) parsedKey);
    }
    if (parsedKey instanceof Ed25519PublicKey) {
      return Ed25519Verify.create((Ed25519PublicKey) parsedKey);
    }
    if (parsedKey instanceof RsaSsaPkcs1PublicKey) {
      return RsaSsaPkcs1VerifyJce.create((RsaSsaPkcs1PublicKey) parsedKey);
    }
    if (parsedKey instanceof RsaSsaPssPublicKey) {
      return RsaSsaPssVerifyJce.create((RsaSsaPssPublicKey) parsedKey);
    }
    throw new GeneralSecurityException(
        "Failed to re-parse LegacyProtoKey for PublicKeyVerify: the parsed key type is"
            + parsedKey.getClass().getName()
            + ", expected one of: EcdsaPublicKey, Ed25519PublicKey, RsaSsaPkcs1PublicKey,"
            + " RsaSsaPssPublicKey.");
  }

  /** Returns an instance of the {@code SignatureConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant SignatureConfigurationV0 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }
}
