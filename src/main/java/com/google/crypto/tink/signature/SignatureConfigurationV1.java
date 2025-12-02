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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.signature.internal.MlDsaSignConscrypt;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.SlhDsaSignConscrypt;
import com.google.crypto.tink.signature.internal.SlhDsaVerifyConscrypt;
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
 * SignatureConfigurationV1 contains the following algorithms for PublicKeySign/Verify:
 *
 * <ul>
 *   <li>Ecdsa
 *   <li>RsaSsaPss
 *   <li>RsaSsaPkcs1
 *   <li>Ed25519
 *   <li>MlDsa65
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class SignatureConfigurationV1 {
  private SignatureConfigurationV1() {}

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
              MlDsaSignConscrypt::create, MlDsaPrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              MlDsaVerifyConscrypt::create, MlDsaPublicKey.class, PublicKeyVerify.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              SlhDsaSignConscrypt::create, SlhDsaPrivateKey.class, PublicKeySign.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              SlhDsaVerifyConscrypt::create, SlhDsaPublicKey.class, PublicKeyVerify.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Returns an instance of the {@code SignatureConfigurationV1}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant SignatureConfigurationV1 in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }
}
