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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.signature.internal.EcdsaKeyCreator;
import com.google.crypto.tink.signature.subtle.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.subtle.EcdsaSigner;
import com.google.crypto.tink.signature.subtle.EcdsaVerifier;
import com.google.crypto.tink.signature.subtle.Ed25519ProtoSerialization;
import com.google.crypto.tink.signature.subtle.Ed25519Signer;
import com.google.crypto.tink.signature.subtle.Ed25519Verifier;
import com.google.crypto.tink.signature.subtle.MlDsaProtoSerialization;
import com.google.crypto.tink.signature.subtle.MlDsaSigner;
import com.google.crypto.tink.signature.subtle.MlDsaVerifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Signer;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Verifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPssProtoSerialization;
import com.google.crypto.tink.signature.subtle.RsaSsaPssSigner;
import com.google.crypto.tink.signature.subtle.RsaSsaPssVerifier;
import com.google.crypto.tink.signature.subtle.SlhDsaProtoSerialization;
import com.google.crypto.tink.signature.subtle.SlhDsaSigner;
import com.google.crypto.tink.signature.subtle.SlhDsaVerifier;
import java.security.GeneralSecurityException;

/**
 * SignatureConfig2026 contains the following algorithms for PublicKeySign/Verify:
 *
 * <ul>
 *   <li>Ecdsa
 *   <li>RsaSsaPss
 *   <li>RsaSsaPkcs1
 *   <li>Ed25519
 *   <li>MlDsa
 *   <li>SlhDsa
 * </ul>
 */
public final class SignatureConfig2026 {
  private SignatureConfig2026() {}

  private static final PublicKeySignWrapper PUBLIC_KEY_SIGN_WRAPPER = new PublicKeySignWrapper();
  private static final PublicKeyVerifyWrapper PUBLIC_KEY_VERIFY_WRAPPER =
      new PublicKeyVerifyWrapper();
  private static final Configuration CONFIGURATION = create();

  /** Returns an instance of the {@code SignatureConfig2026}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant SignatureConfig2026 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static final String ECDSA_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  private static final String ECDSA_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";

  private static final String ED25519_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  private static final String ED25519_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";

  private static final String MLDSA_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  private static final String MLDSA_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

  private static final String RSA_SSA_PKCS1_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  private static final String RSA_SSA_PKCS1_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

  private static final String RSA_SSA_PSS_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  private static final String RSA_SSA_PSS_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

  private static final String SLHDSA_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey";
  private static final String SLHDSA_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(
            PublicKeySign.class, PublicKeySign.class, PUBLIC_KEY_SIGN_WRAPPER::wrap)
        .addPrimitiveWrapper(
            PublicKeyVerify.class, PublicKeyVerify.class, PUBLIC_KEY_VERIFY_WRAPPER::wrap)
        // Ecdsa
        .addPrimitiveConstructor(EcdsaSigner::create, EcdsaPrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(EcdsaVerifier::create, EcdsaPublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(EcdsaPrivateKey.class, EcdsaProtoSerialization::serializePrivateKey)
        .addKeySerializer(EcdsaPublicKey.class, EcdsaProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            EcdsaParameters.class, EcdsaProtoSerialization::serializeParameters)
        .addKeyParser(ECDSA_PRIVATE_KEY_TYPE_URL, EcdsaProtoSerialization::parsePrivateKey)
        .addKeyParser(ECDSA_PUBLIC_KEY_TYPE_URL, EcdsaProtoSerialization::parsePublicKey)
        .addKeyCreator(EcdsaParameters.class, EcdsaKeyCreator::createKey)
        .addParametersParser(ECDSA_PRIVATE_KEY_TYPE_URL, EcdsaProtoSerialization::parseParameters)
        // Ed25519
        .addPrimitiveConstructor(
            Ed25519Signer::create, Ed25519PrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(
            Ed25519Verifier::create, Ed25519PublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(Ed25519PrivateKey.class, Ed25519ProtoSerialization::serializePrivateKey)
        .addKeySerializer(Ed25519PublicKey.class, Ed25519ProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            Ed25519Parameters.class, Ed25519ProtoSerialization::serializeParameters)
        .addKeyParser(ED25519_PRIVATE_KEY_TYPE_URL, Ed25519ProtoSerialization::parsePrivateKey)
        .addKeyParser(ED25519_PUBLIC_KEY_TYPE_URL, Ed25519ProtoSerialization::parsePublicKey)
        .addParametersParser(
            ED25519_PRIVATE_KEY_TYPE_URL, Ed25519ProtoSerialization::parseParameters)
        // MlDsa
        .addPrimitiveConstructor(MlDsaSigner::create, MlDsaPrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(MlDsaVerifier::create, MlDsaPublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(MlDsaPrivateKey.class, MlDsaProtoSerialization::serializePrivateKey)
        .addKeySerializer(MlDsaPublicKey.class, MlDsaProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            MlDsaParameters.class, MlDsaProtoSerialization::serializeParameters)
        .addKeyParser(MLDSA_PRIVATE_KEY_TYPE_URL, MlDsaProtoSerialization::parsePrivateKey)
        .addKeyParser(MLDSA_PUBLIC_KEY_TYPE_URL, MlDsaProtoSerialization::parsePublicKey)
        .addParametersParser(MLDSA_PRIVATE_KEY_TYPE_URL, MlDsaProtoSerialization::parseParameters)
        // RsaSsaPkcs1
        .addPrimitiveConstructor(
            RsaSsaPkcs1Signer::create, RsaSsaPkcs1PrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(
            RsaSsaPkcs1Verifier::create, RsaSsaPkcs1PublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(
            RsaSsaPkcs1PrivateKey.class, RsaSsaPkcs1ProtoSerialization::serializePrivateKey)
        .addKeySerializer(
            RsaSsaPkcs1PublicKey.class, RsaSsaPkcs1ProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            RsaSsaPkcs1Parameters.class, RsaSsaPkcs1ProtoSerialization::serializeParameters)
        .addKeyParser(
            RSA_SSA_PKCS1_PRIVATE_KEY_TYPE_URL, RsaSsaPkcs1ProtoSerialization::parsePrivateKey)
        .addKeyParser(
            RSA_SSA_PKCS1_PUBLIC_KEY_TYPE_URL, RsaSsaPkcs1ProtoSerialization::parsePublicKey)
        .addParametersParser(
            RSA_SSA_PKCS1_PRIVATE_KEY_TYPE_URL, RsaSsaPkcs1ProtoSerialization::parseParameters)
        // RsaSsaPss
        .addPrimitiveConstructor(
            RsaSsaPssSigner::create, RsaSsaPssPrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(
            RsaSsaPssVerifier::create, RsaSsaPssPublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(
            RsaSsaPssPrivateKey.class, RsaSsaPssProtoSerialization::serializePrivateKey)
        .addKeySerializer(RsaSsaPssPublicKey.class, RsaSsaPssProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            RsaSsaPssParameters.class, RsaSsaPssProtoSerialization::serializeParameters)
        .addKeyParser(
            RSA_SSA_PSS_PRIVATE_KEY_TYPE_URL, RsaSsaPssProtoSerialization::parsePrivateKey)
        .addKeyParser(RSA_SSA_PSS_PUBLIC_KEY_TYPE_URL, RsaSsaPssProtoSerialization::parsePublicKey)
        .addParametersParser(
            RSA_SSA_PSS_PRIVATE_KEY_TYPE_URL, RsaSsaPssProtoSerialization::parseParameters)
        // SlhDsa
        .addPrimitiveConstructor(SlhDsaSigner::create, SlhDsaPrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(
            SlhDsaVerifier::create, SlhDsaPublicKey.class, PublicKeyVerify.class)
        .addKeySerializer(SlhDsaPrivateKey.class, SlhDsaProtoSerialization::serializePrivateKey)
        .addKeySerializer(SlhDsaPublicKey.class, SlhDsaProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            SlhDsaParameters.class, SlhDsaProtoSerialization::serializeParameters)
        .addKeyParser(SLHDSA_PRIVATE_KEY_TYPE_URL, SlhDsaProtoSerialization::parsePrivateKey)
        .addKeyParser(SLHDSA_PUBLIC_KEY_TYPE_URL, SlhDsaProtoSerialization::parsePublicKey)
        .addParametersParser(SLHDSA_PRIVATE_KEY_TYPE_URL, SlhDsaProtoSerialization::parseParameters)
        .build();
  }
}

