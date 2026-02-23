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
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
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

  private static final PublicKeySignWrapper PUBLIC_KEY_SIGN_WRAPPER = new PublicKeySignWrapper();
  private static final PublicKeyVerifyWrapper PUBLIC_KEY_VERIFY_WRAPPER =
      new PublicKeyVerifyWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == PublicKeySign.class) {
          return clazz.cast(
              PUBLIC_KEY_SIGN_WRAPPER.wrap(
                  keysetHandle, SignatureConfigurationV0::createPublicKeySign));
        }
        if (clazz == PublicKeyVerify.class) {
          return clazz.cast(
              PUBLIC_KEY_VERIFY_WRAPPER.wrap(
                  keysetHandle, SignatureConfigurationV0::createPublicKeyVerify));
        }
        throw new GeneralSecurityException(
            "SignatureConfigurationV0 can only create PublicKeySign and PublicKeyVerify");
      }
    };
  }

  /** Returns an instance of the {@code SignatureConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant SignatureConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static PublicKeySign createPublicKeySign(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof LegacyProtoKey) {
      Key reparsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  ((LegacyProtoKey) key).getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      key = reparsedKey;
    }
    if (key instanceof EcdsaPrivateKey) {
      return EcdsaSignJce.create((EcdsaPrivateKey) key);
    }
    if (key instanceof RsaSsaPssPrivateKey) {
      return RsaSsaPssSignJce.create((RsaSsaPssPrivateKey) key);
    }
    if (key instanceof RsaSsaPkcs1PrivateKey) {
      return RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) key);
    }
    if (key instanceof Ed25519PrivateKey) {
      return Ed25519Sign.create((Ed25519PrivateKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  private static PublicKeyVerify createPublicKeyVerify(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof LegacyProtoKey) {
      Key reparsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  ((LegacyProtoKey) key).getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      key = reparsedKey;
    }
    if (key instanceof EcdsaPublicKey) {
      return EcdsaVerifyJce.create((EcdsaPublicKey) key);
    }
    if (key instanceof RsaSsaPssPublicKey) {
      return RsaSsaPssVerifyJce.create((RsaSsaPssPublicKey) key);
    }
    if (key instanceof RsaSsaPkcs1PublicKey) {
      return RsaSsaPkcs1VerifyJce.create((RsaSsaPkcs1PublicKey) key);
    }
    if (key instanceof Ed25519PublicKey) {
      return Ed25519Verify.create((Ed25519PublicKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }
}
