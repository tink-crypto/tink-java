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
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.signature.subtle.EcdsaSigner;
import com.google.crypto.tink.signature.subtle.EcdsaVerifier;
import com.google.crypto.tink.signature.subtle.Ed25519Signer;
import com.google.crypto.tink.signature.subtle.Ed25519Verifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Signer;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Verifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPssSigner;
import com.google.crypto.tink.signature.subtle.RsaSsaPssVerifier;
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

  private static final Configuration CONFIGURATION = create();

  /** Returns an instance of the {@code SignatureConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant SignatureConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  @LowLevelCryptoCaller
  private static Configuration create() {
    // The SignatureConfigurationV0 is the same as the SignatureConfig, but if a key has been
    // parsed as a LegacyProtoKey (which happens if we use the RegistryConfig and the corresponding
    // algorithm was not registered), we try to parse it again.
    return new ProtoBasedConfigurationBuilder()
        .mergeProtoBasedConfiguration(SignatureConfig2026.get())
        .addPrimitiveConstructor(
            SignatureConfigurationV0::createPublicKeySignFromLegacyProtoKey,
            LegacyProtoKey.class,
            PublicKeySign.class)
        .addPrimitiveConstructor(
            SignatureConfigurationV0::createPublicKeyVerifyFromLegacyProtoKey,
            LegacyProtoKey.class,
            PublicKeyVerify.class)
        .build();
  }

  @LowLevelCryptoCaller
  private static Key reparseKey(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerializer protoKeySerializer = get().getOrNull(ProtoKeySerializer.class);
    if (protoKeySerializer == null) {
      throw new GeneralSecurityException(
          "Unexpected: CONFIGURATION does not support Proto Serialization");
    }
    return protoKeySerializer.parseKey(
        key.getSerialization(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
  }

  @LowLevelCryptoCaller
  private static PublicKeySign createPublicKeySignFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof EcdsaPrivateKey) {
      return EcdsaSigner.create((EcdsaPrivateKey) reparsedKey);
    }
    if (reparsedKey instanceof RsaSsaPssPrivateKey) {
      return RsaSsaPssSigner.create((RsaSsaPssPrivateKey) reparsedKey);
    }
    if (reparsedKey instanceof RsaSsaPkcs1PrivateKey) {
      return RsaSsaPkcs1Signer.create((RsaSsaPkcs1PrivateKey) reparsedKey);
    }
    if (reparsedKey instanceof Ed25519PrivateKey) {
      return Ed25519Signer.create((Ed25519PrivateKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }

  @LowLevelCryptoCaller
  private static PublicKeyVerify createPublicKeyVerifyFromLegacyProtoKey(LegacyProtoKey key)
      throws GeneralSecurityException {
    Key reparsedKey = reparseKey(key);
    if (reparsedKey instanceof EcdsaPublicKey) {
      return EcdsaVerifier.create((EcdsaPublicKey) reparsedKey);
    }
    if (reparsedKey instanceof RsaSsaPssPublicKey) {
      return RsaSsaPssVerifier.create((RsaSsaPssPublicKey) reparsedKey);
    }
    if (reparsedKey instanceof RsaSsaPkcs1PublicKey) {
      return RsaSsaPkcs1Verifier.create((RsaSsaPkcs1PublicKey) reparsedKey);
    }
    if (reparsedKey instanceof Ed25519PublicKey) {
      return Ed25519Verifier.create((Ed25519PublicKey) reparsedKey);
    }
    throw new GeneralSecurityException("Unknown key class: " + reparsedKey.getClass());
  }
}
