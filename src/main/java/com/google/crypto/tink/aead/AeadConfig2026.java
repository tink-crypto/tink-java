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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.aead.internal.WrappedAead;
import com.google.crypto.tink.aead.subtle.AesCtrHmacAead;
import com.google.crypto.tink.aead.subtle.AesCtrHmacAeadProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesEaxAead;
import com.google.crypto.tink.aead.subtle.AesEaxProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesGcmAead;
import com.google.crypto.tink.aead.subtle.AesGcmProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesGcmSivAead;
import com.google.crypto.tink.aead.subtle.AesGcmSivProtoSerialization;
import com.google.crypto.tink.aead.subtle.ChaCha20Poly1305Aead;
import com.google.crypto.tink.aead.subtle.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.aead.subtle.XAesGcmAead;
import com.google.crypto.tink.aead.subtle.XAesGcmProtoSerialization;
import com.google.crypto.tink.aead.subtle.XChaCha20Poly1305Aead;
import com.google.crypto.tink.aead.subtle.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * AeadConfig2026 contains the following primitives and algorithms for {@link Aead}:
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
 *
 * <h3>FIPS Mode</h3>
 *
 * <p>When Tink is configured in FIPS-only mode (via {@link TinkFipsUtil#useOnlyFips()}), calling
 * {@link #get()} returns the {@link Configuration} instance. However, non-FIPS-validated algorithms
 * (e.g., AesEax, ChaCha20Poly1305, XChaCha20Poly1305, XAesGcm) will fail at key creation or
 * primitive retrieval time with a {@link GeneralSecurityException}.
 *
 * <h3>AesGcmSiv</h3>
 *
 * <p>All algorithms are supported out of the box, with the following requirement for
 * <b>AES-GCM-SIV</b>:
 *
 * <ul>
 *   <li><b>AES-GCM-SIV</b> requires either Android API level 30+ or Conscrypt registered as a
 *       security provider (e.g., via {@code Security.addProvider(Conscrypt.newProvider())}). On
 *       non-Android Java environments without Conscrypt, or on Android API levels below 30 without
 *       Conscrypt, attempting to obtain an {@link Aead} primitive for an {@code AesGcmSivKey} will
 *       throw a {@link GeneralSecurityException}.
 * </ul>
 */
public final class AeadConfig2026 {
  private AeadConfig2026() {}

  private static final Configuration CONFIGURATION = create();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    return CONFIGURATION;
  }

  private static final String AES_CTR_HMAC_AEAD_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  private static final String AES_GCM_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
  private static final String AES_GCM_SIV_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmSivKey";
  private static final String AES_EAX_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesEaxKey";
  private static final String CHACHA20_POLY1305_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";
  private static final String XCHACHA20_POLY1305_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  private static final String XAES_GCM_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.XAesGcmKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(
            Aead.class,
            Aead.class,
            WrappedAead::create)
        // AesCtrHmac
        .addKeyCreator(AesCtrHmacAeadParameters.class, AeadConfig2026::createAesCtrHmacAeadKey)
        .addPrimitiveConstructor(
            AesCtrHmacAead::create,
            AesCtrHmacAeadKey.class,
            Aead.class)
        .addKeySerializer(AesCtrHmacAeadKey.class, AesCtrHmacAeadProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesCtrHmacAeadParameters.class, AesCtrHmacAeadProtoSerialization::serializeParameters)
        .addKeyParser(AES_CTR_HMAC_AEAD_TYPE_URL, AesCtrHmacAeadProtoSerialization::parseKey)
        .addParametersParser(
            AES_CTR_HMAC_AEAD_TYPE_URL, AesCtrHmacAeadProtoSerialization::parseParameters)
        // AesGcm
        .addKeyCreator(AesGcmParameters.class, AeadConfig2026::createAesGcmKey)
        .addPrimitiveConstructor(
            AesGcmAead::create,
            AesGcmKey.class,
            Aead.class)
        .addKeySerializer(AesGcmKey.class, AesGcmProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
        .addKeyParser(AES_GCM_TYPE_URL, AesGcmProtoSerialization::parseKey)
        .addParametersParser(AES_GCM_TYPE_URL, AesGcmProtoSerialization::parseParameters)
        // AesGcmSiv
        .addKeyCreator(AesGcmSivParameters.class, AeadConfig2026::createAesGcmSivKey)
        .addPrimitiveConstructor(
            AesGcmSivAead::create,
            AesGcmSivKey.class,
            Aead.class)
        .addKeySerializer(AesGcmSivKey.class, AesGcmSivProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesGcmSivParameters.class, AesGcmSivProtoSerialization::serializeParameters)
        .addKeyParser(AES_GCM_SIV_TYPE_URL, AesGcmSivProtoSerialization::parseKey)
        .addParametersParser(AES_GCM_SIV_TYPE_URL, AesGcmSivProtoSerialization::parseParameters)
        // AesEax
        .addKeyCreator(AesEaxParameters.class, AeadConfig2026::createAesEaxKey)
        .addPrimitiveConstructor(
            AesEaxAead::create,
            AesEaxKey.class,
            Aead.class)
        .addKeySerializer(AesEaxKey.class, AesEaxProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesEaxParameters.class, AesEaxProtoSerialization::serializeParameters)
        .addKeyParser(AES_EAX_TYPE_URL, AesEaxProtoSerialization::parseKey)
        .addParametersParser(AES_EAX_TYPE_URL, AesEaxProtoSerialization::parseParameters)
        // ChaCha20Poly1305
        .addKeyCreator(ChaCha20Poly1305Parameters.class, AeadConfig2026::createChaCha20Poly1305Key)
        .addPrimitiveConstructor(
            ChaCha20Poly1305Aead::create,
            ChaCha20Poly1305Key.class,
            Aead.class)
        .addKeySerializer(
            ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey)
        .addParametersSerializer(
            ChaCha20Poly1305Parameters.class,
            ChaCha20Poly1305ProtoSerialization::serializeParameters)
        .addKeyParser(CHACHA20_POLY1305_TYPE_URL, ChaCha20Poly1305ProtoSerialization::parseKey)
        .addParametersParser(
            CHACHA20_POLY1305_TYPE_URL, ChaCha20Poly1305ProtoSerialization::parseParameters)
        // XChaCha20Poly1305
        .addKeyCreator(XChaCha20Poly1305Parameters.class, AeadConfig2026::createXChaCha20Poly1305Key)
        .addPrimitiveConstructor(
            XChaCha20Poly1305Aead::create,
            XChaCha20Poly1305Key.class,
            Aead.class)
        .addKeySerializer(
            XChaCha20Poly1305Key.class, XChaCha20Poly1305ProtoSerialization::serializeKey)
        .addParametersSerializer(
            XChaCha20Poly1305Parameters.class,
            XChaCha20Poly1305ProtoSerialization::serializeParameters)
        .addKeyParser(XCHACHA20_POLY1305_TYPE_URL, XChaCha20Poly1305ProtoSerialization::parseKey)
        .addParametersParser(
            XCHACHA20_POLY1305_TYPE_URL, XChaCha20Poly1305ProtoSerialization::parseParameters)
        // XAesGcm
        .addKeyCreator(XAesGcmParameters.class, AeadConfig2026::createXAesGcmKey)
        .addPrimitiveConstructor(
            XAesGcmAead::create,
            XAesGcmKey.class,
            Aead.class)
        .addKeySerializer(XAesGcmKey.class, XAesGcmProtoSerialization::serializeKey)
        .addParametersSerializer(
            XAesGcmParameters.class, XAesGcmProtoSerialization::serializeParameters)
        .addKeyParser(XAES_GCM_TYPE_URL, XAesGcmProtoSerialization::parseKey)
        .addParametersParser(XAES_GCM_TYPE_URL, XAesGcmProtoSerialization::parseParameters)
        .build();
  }

  @AccessesPartialKey
  private static AesCtrHmacAeadKey createAesCtrHmacAeadKey(
      AesCtrHmacAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-CTR-HMAC in FIPS-mode");
    }
    return AesCtrHmacAeadKey.builder()
        .setParameters(parameters)
        .setAesKeyBytes(SecretBytes.randomBytes(parameters.getAesKeySizeBytes()))
        .setHmacKeyBytes(SecretBytes.randomBytes(parameters.getHmacKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @AccessesPartialKey
  private static AesGcmKey createAesGcmKey(
      AesGcmParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-GCM in FIPS-mode");
    }
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @AccessesPartialKey
  private static AesGcmSivKey createAesGcmSivKey(
      AesGcmSivParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-GCM-SIV in FIPS-mode");
    }
    return AesGcmSivKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @AccessesPartialKey
  private static AesEaxKey createAesEaxKey(
      AesEaxParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-EAX in FIPS-mode");
    }
    return AesEaxKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @AccessesPartialKey
  private static ChaCha20Poly1305Key createChaCha20Poly1305Key(
      ChaCha20Poly1305Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use ChaCha20Poly1305 in FIPS-mode");
    }
    return ChaCha20Poly1305Key.create(
        parameters.getVariant(), SecretBytes.randomBytes(32), idRequirement);
  }

  @AccessesPartialKey
  private static XChaCha20Poly1305Key createXChaCha20Poly1305Key(
      XChaCha20Poly1305Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use XChaCha20Poly1305 in FIPS-mode");
    }
    return XChaCha20Poly1305Key.create(
        parameters.getVariant(), SecretBytes.randomBytes(32), idRequirement);
  }

  @AccessesPartialKey
  private static XAesGcmKey createXAesGcmKey(
      XAesGcmParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use XAesGcm in FIPS-mode");
    }
    return XAesGcmKey.create(
        parameters, SecretBytes.randomBytes(32), idRequirement);
  }
}
