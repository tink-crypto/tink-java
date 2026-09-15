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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeyVerify;
import java.security.GeneralSecurityException;

/**
 * JwtSignatureConfigurationV0 contains the following algorithms for JWT:
 *
 * <ul>
 *   <li>EcdsaSign/Verify
 *   <li>MlDsaSign/Verify
 *   <li>RsaSsaPkcs1Sign/Verify
 *   <li>RsaSsaPssSign/Verify
 * </ul>
 */
@LowLevelCryptoCaller
/* Placeholder for internally public; DO NOT CHANGE. */ class JwtSignatureConfigurationV0 {
  private JwtSignatureConfigurationV0() {}

  private static final JwtPublicKeySignWrapper JWT_PUBLIC_KEY_SIGN_WRAPPER =
      new JwtPublicKeySignWrapper();
  private static final JwtPublicKeyVerifyWrapper JWT_PUBLIC_KEY_VERIFY_WRAPPER =
      new JwtPublicKeyVerifyWrapper();
  private static final Configuration CONFIGURATION = create();

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == JwtPublicKeySign.class) {
          return clazz.cast(
              JWT_PUBLIC_KEY_SIGN_WRAPPER.wrap(
                  keysetHandle, JwtSignatureConfigurationV0::createJwtPublicKeySign));
        }
        if (clazz == JwtPublicKeyVerify.class) {
          return clazz.cast(
              JWT_PUBLIC_KEY_VERIFY_WRAPPER.wrap(
                  keysetHandle, JwtSignatureConfigurationV0::createJwtPublicKeyVerify));
        }
        throw new GeneralSecurityException(
            "JwtSignatureConfigurationV0 can only create JwtPublicKeySign and JwtPublicKeyVerify");
      }
    };
  }

  private static JwtPublicKeySign createJwtPublicKeySign(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof JwtEcdsaPrivateKey) {
      return JwtEcdsaPublicKeySign.create((JwtEcdsaPrivateKey) key);
    }
    if (key instanceof JwtMlDsaPrivateKey) {
      return JwtMlDsaPublicKeySign.create((JwtMlDsaPrivateKey) key);
    }
    if (key instanceof JwtRsaSsaPkcs1PrivateKey) {
      return JwtRsaSsaPkcs1PublicKeySign.create((JwtRsaSsaPkcs1PrivateKey) key);
    }
    if (key instanceof JwtRsaSsaPssPrivateKey) {
      return JwtRsaSsaPssPublicKeySign.create((JwtRsaSsaPssPrivateKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  private static JwtPublicKeyVerify createJwtPublicKeyVerify(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof JwtEcdsaPublicKey) {
      return JwtEcdsaPublicKeyVerify.create((JwtEcdsaPublicKey) key);
    }
    if (key instanceof JwtMlDsaPublicKey) {
      return JwtMlDsaPublicKeyVerify.create((JwtMlDsaPublicKey) key);
    }
    if (key instanceof JwtRsaSsaPkcs1PublicKey) {
      return JwtRsaSsaPkcs1PublicKeyVerify.create((JwtRsaSsaPkcs1PublicKey) key);
    }
    if (key instanceof JwtRsaSsaPssPublicKey) {
      return JwtRsaSsaPssPublicKeyVerify.create((JwtRsaSsaPssPublicKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  /** Returns an instance of the {@code JwtSignatureConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use JwtSignatureConfigurationV0, as BoringCrypto module is needed for FIPS"
              + " compatibility");
    }
    return CONFIGURATION;
  }
}
