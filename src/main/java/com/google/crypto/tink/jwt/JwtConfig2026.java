// Copyright 2026 Google LLC
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
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtHmac;
import com.google.crypto.tink.jwt.subtle.JwtHmacProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssProtoSerialization;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeyVerify;
import java.security.GeneralSecurityException;

/**
 * JwtConfig2026 contains the following primitives and algorithms for JWT:
 *
 * <ul>
 *   <li>JwtMac
 *       <ul>
 *         <li>JwtHmac
 *       </ul>
 *   <li>JwtPublicKeySign / JwtPublicKeyVerify
 *       <ul>
 *         <li>JwtEcdsa
 *         <li>JwtRsaSsaPkcs1
 *         <li>JwtRsaSsaPss
 *         <li>JwtMlDsa
 *       </ul>
 * </ul>
 */
public class JwtConfig2026 {

  private JwtConfig2026() {}

  private static final Configuration CONFIG = buildConfiguration();

  @LowLevelCryptoCaller
  private static Configuration buildConfiguration() {
    return new ProtoBasedConfigurationBuilder()
        // =========== JwtMac
        .addPrimitiveWrapper(
            JwtMac.class,
            JwtMac.class,
            (handle, factory) -> new JwtMacWrapper().wrap(handle, factory))
        // JwtHmacMac
        .addPrimitiveConstructor(JwtHmac::create, JwtHmacKey.class, JwtMac.class)
        .addKeySerializer(JwtHmacKey.class, JwtHmacProtoSerialization::serializeKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            JwtHmacProtoSerialization::parseKey)
        .addParametersSerializer(
            JwtHmacParameters.class, JwtHmacProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            JwtHmacProtoSerialization::parseParameters)
        // =========== JwtPublicKeySign & JwtPublicKeyVerify
        .addPrimitiveWrapper(
            JwtPublicKeySign.class,
            JwtPublicKeySign.class,
            (handle, factory) -> new JwtPublicKeySignWrapper().wrap(handle, factory))
        .addPrimitiveWrapper(
            JwtPublicKeyVerify.class,
            JwtPublicKeyVerify.class,
            (handle, factory) -> new JwtPublicKeyVerifyWrapper().wrap(handle, factory))
        // JwtEcdsa
        .addPrimitiveConstructor(
            JwtEcdsaPublicKeySign::create, JwtEcdsaPrivateKey.class, JwtPublicKeySign.class)
        .addPrimitiveConstructor(
            JwtEcdsaPublicKeyVerify::create, JwtEcdsaPublicKey.class, JwtPublicKeyVerify.class)
        .addKeySerializer(JwtEcdsaPrivateKey.class, JwtEcdsaProtoSerialization::serializePrivateKey)
        .addKeySerializer(JwtEcdsaPublicKey.class, JwtEcdsaProtoSerialization::serializePublicKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
            JwtEcdsaProtoSerialization::parsePrivateKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            JwtEcdsaProtoSerialization::parsePublicKey)
        .addParametersSerializer(
            JwtEcdsaParameters.class, JwtEcdsaProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
            JwtEcdsaProtoSerialization::parseParameters)
        // JwtRsaSsaPkcs1
        .addPrimitiveConstructor(
            JwtRsaSsaPkcs1PublicKeySign::create,
            JwtRsaSsaPkcs1PrivateKey.class,
            JwtPublicKeySign.class)
        .addPrimitiveConstructor(
            JwtRsaSsaPkcs1PublicKeyVerify::create,
            JwtRsaSsaPkcs1PublicKey.class,
            JwtPublicKeyVerify.class)
        .addKeySerializer(
            JwtRsaSsaPkcs1PrivateKey.class, JwtRsaSsaPkcs1ProtoSerialization::serializePrivateKey)
        .addKeySerializer(
            JwtRsaSsaPkcs1PublicKey.class, JwtRsaSsaPkcs1ProtoSerialization::serializePublicKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
            JwtRsaSsaPkcs1ProtoSerialization::parsePrivateKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            JwtRsaSsaPkcs1ProtoSerialization::parsePublicKey)
        .addParametersSerializer(
            JwtRsaSsaPkcs1Parameters.class, JwtRsaSsaPkcs1ProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
            JwtRsaSsaPkcs1ProtoSerialization::parseParameters)
        // JwtRsaSsaPss
        .addPrimitiveConstructor(
            JwtRsaSsaPssPublicKeySign::create, JwtRsaSsaPssPrivateKey.class, JwtPublicKeySign.class)
        .addPrimitiveConstructor(
            JwtRsaSsaPssPublicKeyVerify::create,
            JwtRsaSsaPssPublicKey.class,
            JwtPublicKeyVerify.class)
        .addKeySerializer(
            JwtRsaSsaPssPrivateKey.class, JwtRsaSsaPssProtoSerialization::serializePrivateKey)
        .addKeySerializer(
            JwtRsaSsaPssPublicKey.class, JwtRsaSsaPssProtoSerialization::serializePublicKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
            JwtRsaSsaPssProtoSerialization::parsePrivateKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            JwtRsaSsaPssProtoSerialization::parsePublicKey)
        .addParametersSerializer(
            JwtRsaSsaPssParameters.class, JwtRsaSsaPssProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
            JwtRsaSsaPssProtoSerialization::parseParameters)
        // JwtMlDsa
        .addPrimitiveConstructor(
            JwtMlDsaPublicKeySign::create, JwtMlDsaPrivateKey.class, JwtPublicKeySign.class)
        .addPrimitiveConstructor(
            JwtMlDsaPublicKeyVerify::create, JwtMlDsaPublicKey.class, JwtPublicKeyVerify.class)
        .addKeySerializer(
            JwtMlDsaPrivateKey.class, JwtMlDsaProtoSerialization::serializePrivateKey)
        .addKeySerializer(
            JwtMlDsaPublicKey.class, JwtMlDsaProtoSerialization::serializePublicKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
            JwtMlDsaProtoSerialization::parsePrivateKey)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
            JwtMlDsaProtoSerialization::parsePublicKey)
        .addParametersSerializer(
            JwtMlDsaParameters.class, JwtMlDsaProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey",
            JwtMlDsaProtoSerialization::parseParameters)
        .build();
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant JwtConfig2026 in FIPS mode");
    }
    return CONFIG;
  }
}
