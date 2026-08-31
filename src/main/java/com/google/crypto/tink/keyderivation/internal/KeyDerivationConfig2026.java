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

package com.google.crypto.tink.keyderivation.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesCtrHmacAeadProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesGcmProtoSerialization;
import com.google.crypto.tink.aead.subtle.AesGcmSivProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.subtle.AesSivProtoSerialization;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.subtle.HmacProtoSerialization;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.HmacPrfParameters;
import com.google.crypto.tink.prf.subtle.HkdfPrfProtoSerialization;
import com.google.crypto.tink.prf.subtle.HmacPrfProtoSerialization;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.subtle.Ed25519ProtoSerialization;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import com.google.crypto.tink.streamingaead.internal.AesGcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * KeyDerivationConfig2026 contains the following primitives and algorithms for {@link
 * KeysetDeriver}:
 *
 * <ul>
 *   <li>HKDF-PRF-based key derivation
 * </ul>
 */
@LowLevelCryptoCaller
public final class KeyDerivationConfig2026 {
  private KeyDerivationConfig2026() {}

  // This is the configuration which the {@link PrfBasedKeyDerivationKeyProtoSerialization} uses to
  // internally serialize PRF keys and derived parameters, as well as derive keys from randomness.
  // It hence includes the following key types:
  // ==== Key types which can be used to derive new keys (need key and parameter serialization)
  //  * HkdfPrf
  // ==== Key types which can only be derived (need parameter serialization and KeyFromRandomness)
  //  * Hmac
  //  * HmacPrf
  //  * AesGcm
  //  * AesCtrHmacAead
  //  * XChaCha20Poly1305
  //  * AesSiv
  //  * AesGcmSiv
  //  * AesGcmHkdfStreaming
  //  * Ed25519
  private static PrfBasedKeyDerivationKeyConfig keyDerivationKeyConfig() {
    return new PrfBasedKeyDerivationKeyConfigBuilder()
        // HkdfPrf
        .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
        .addParametersSerializer(
            HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
            HkdfPrfProtoSerialization::parseKey)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
            HkdfPrfProtoSerialization::parseParameters)
        // Hmac
        .addParametersSerializer(HmacParameters.class, HmacProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            HmacProtoSerialization::parseParameters)
        .addKeyFromRandomness(HmacParameters.class, KeyDerivationConfig2026::createHmacKey)
        // HmacPrf
        .addParametersSerializer(
            HmacPrfParameters.class, HmacPrfProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.HmacPrfKey",
            HmacPrfProtoSerialization::parseParameters)
        .addKeyFromRandomness(HmacPrfParameters.class, KeyDerivationConfig2026::createHmacPrfKey)
        // AesGcm
        .addParametersSerializer(
            AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.AesGcmKey",
            AesGcmProtoSerialization::parseParameters)
        .addKeyFromRandomness(AesGcmParameters.class, KeyDerivationConfig2026::createAesGcmKey)
        // AesCtrHmacAead
        .addParametersSerializer(
            AesCtrHmacAeadParameters.class, AesCtrHmacAeadProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            AesCtrHmacAeadProtoSerialization::parseParameters)
        .addKeyFromRandomness(
            AesCtrHmacAeadParameters.class, KeyDerivationConfig2026::createAesCtrHmacAeadKey)
        // XChaCha20Poly1305
        .addParametersSerializer(
            XChaCha20Poly1305Parameters.class,
            XChaCha20Poly1305ProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            XChaCha20Poly1305ProtoSerialization::parseParameters)
        .addKeyFromRandomness(
            XChaCha20Poly1305Parameters.class, KeyDerivationConfig2026::createXChaCha20Poly1305Key)
        // AesSiv
        .addParametersSerializer(
            AesSivParameters.class, AesSivProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.AesSivKey",
            AesSivProtoSerialization::parseParameters)
        .addKeyFromRandomness(AesSivParameters.class, KeyDerivationConfig2026::createAesSivKey)
        // AesGcmSiv
        .addParametersSerializer(
            AesGcmSivParameters.class, AesGcmSivProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
            AesGcmSivProtoSerialization::parseParameters)
        .addKeyFromRandomness(
            AesGcmSivParameters.class, KeyDerivationConfig2026::createAesGcmSivKey)
        // AesGcmHkdfStreaming
        .addParametersSerializer(
            AesGcmHkdfStreamingParameters.class,
            AesGcmHkdfStreamingProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            AesGcmHkdfStreamingProtoSerialization::parseParameters)
        .addKeyFromRandomness(
            AesGcmHkdfStreamingParameters.class,
            KeyDerivationConfig2026::createAesGcmHkdfStreamingKey)
        // Ed25519
        .addParametersSerializer(
            Ed25519Parameters.class, Ed25519ProtoSerialization::serializeParameters)
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            Ed25519ProtoSerialization::parseParameters)
        .addKeyFromRandomness(Ed25519Parameters.class, KeyDerivationConfig2026::createEd25519Key)
        .build();
  }

  private static Configuration createConfiguration(
      PrfBasedKeyDerivationKeyConfig keyDerivationKeyConfig) {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(
            KeysetDeriver.class, KeyDeriver.class, KeysetDeriverWrapper.WRAPPER::wrap)
        // PrfBasedKeyDerivation
        .addKeyCreator(
            PrfBasedKeyDerivationParameters.class,
            KeyDerivationConfig2026::createPrfBasedKeyDerivationKey)
        .addPrimitiveConstructor(
            (PrfBasedKeyDerivationKey key) ->
                createPrfBasedKeyDeriver(key, keyDerivationKeyConfig),
            PrfBasedKeyDerivationKey.class,
            KeyDeriver.class)
        .addKeySerializer(
            PrfBasedKeyDerivationKey.class,
            (key, access) ->
                PrfBasedKeyDerivationKeyProtoSerialization.serializeKey(
                    key, access, keyDerivationKeyConfig.getConfiguration()))
        .addParametersSerializer(
            PrfBasedKeyDerivationParameters.class,
            parameters ->
                PrfBasedKeyDerivationKeyProtoSerialization.serializeParameters(
                    parameters, keyDerivationKeyConfig.getConfiguration()))
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            (serialization, access) ->
                PrfBasedKeyDerivationKeyProtoSerialization.parseKey(
                    serialization, access, keyDerivationKeyConfig.getConfiguration()))
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            serialization ->
                PrfBasedKeyDerivationKeyProtoSerialization.parseParameters(
                    serialization, keyDerivationKeyConfig.getConfiguration()))
        .build();
  }

  private static final Configuration CONFIGURATION =
      createConfiguration(keyDerivationKeyConfig());
  private static final Configuration EMPTY_CONFIGURATION =
      new ProtoBasedConfigurationBuilder().build();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    if (TinkFipsUtil.useOnlyFips()) {
      return EMPTY_CONFIGURATION;
    }
    return CONFIGURATION;
  }

  // We hard code here the list of supported keys we can derive. It might be that this should
  // even be hard coded in PrfBasedDerivationKey instead (since it really cannot change, ever). But
  // right now we hard code it here (at least partially because for some users we might want to
  // extend the list with keys which are not available for everyone).
  // The supported keys are:
  //  * Hmac
  //  * HmacPrf
  //  * AesGcm
  //  * AesCtrHmacAead
  //  * XChaCha20Poly1305
  //  * AesSiv
  //  * AesGcmSiv
  //  * AesGcmHkdfStreaming
  //  * Ed25519
  @AccessesPartialKey
  private static Key createHmacKey(
      HmacParameters hmacParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return HmacKey.builder()
        .setParameters(hmacParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, hmacParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createHmacPrfKey(
      HmacPrfParameters hmacPrfParameters,
      InputStream stream,
      @SuppressWarnings("unused") @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return HmacPrfKey.builder()
        .setParameters(hmacPrfParameters)
        .setKeyBytes(Util.readIntoSecretBytes(stream, hmacPrfParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createAesGcmKey(
      AesGcmParameters aesGcmParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesGcmKey.builder()
        .setParameters(aesGcmParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, aesGcmParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createAesCtrHmacAeadKey(
      AesCtrHmacAeadParameters aesCtrHmacParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesCtrHmacAeadKey.builder()
        .setParameters(aesCtrHmacParameters)
        .setIdRequirement(idRequirement)
        .setAesKeyBytes(
            Util.readIntoSecretBytes(stream, aesCtrHmacParameters.getAesKeySizeBytes(), access))
        .setHmacKeyBytes(
            Util.readIntoSecretBytes(stream, aesCtrHmacParameters.getHmacKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createXChaCha20Poly1305Key(
      XChaCha20Poly1305Parameters xChaCha20Poly1305Parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return XChaCha20Poly1305Key.create(
        xChaCha20Poly1305Parameters.getVariant(),
        Util.readIntoSecretBytes(stream, 32, access),
        idRequirement);
  }

  @AccessesPartialKey
  private static Key createAesSivKey(
      AesSivParameters aesSivParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesSivKey.builder()
        .setParameters(aesSivParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, aesSivParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createAesGcmSivKey(
      AesGcmSivParameters aesGcmSivParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesGcmSivKey.builder()
        .setParameters(aesGcmSivParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(
            Util.readIntoSecretBytes(stream, aesGcmSivParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createAesGcmHkdfStreamingKey(
      AesGcmHkdfStreamingParameters streamingParameters,
      InputStream stream,
      @SuppressWarnings("unused") @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesGcmHkdfStreamingKey.create(
        streamingParameters,
        Util.readIntoSecretBytes(stream, streamingParameters.getKeySizeBytes(), access));
  }

  @AccessesPartialKey
  private static Key createEd25519Key(
      Ed25519Parameters ed25519Parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretBytes pseudorandomness =
        Util.readIntoSecretBytes(stream, Ed25519Sign.SECRET_KEY_LEN, access);
    Ed25519Sign.KeyPair keyPair =
        Ed25519Sign.KeyPair.newKeyPairFromSeed(pseudorandomness.toByteArray(access));
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            ed25519Parameters.getVariant(), Bytes.copyFrom(keyPair.getPublicKey()), idRequirement);
    return Ed25519PrivateKey.create(
        publicKey, SecretBytes.copyFrom(keyPair.getPrivateKey(), access));
  }

  @AccessesPartialKey
  private static KeyDeriver createPrfBasedKeyDeriver(
      PrfBasedKeyDerivationKey key, PrfBasedKeyDerivationKeyConfig keyDerivationKeyConfig)
      throws GeneralSecurityException {
    return PrfBasedKeyDeriver.create(
        k -> {
          if (k instanceof HkdfPrfKey) {
            return HkdfStreamingPrf.create((HkdfPrfKey) k);
          }
          throw new GeneralSecurityException("Unsupported PRF key type: " + k.getClass());
        },
        keyDerivationKeyConfig::createKeyFromRandomness,
        key);
  }

  @AccessesPartialKey
  private static HkdfPrfKey createHkdfPrfKey(
      HkdfPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("PRF Keys are not expected to have an id Requirement");
    }
    return HkdfPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @AccessesPartialKey
  @LowLevelCryptoCaller
  private static PrfBasedKeyDerivationKey createPrfBasedKeyDerivationKey(
      PrfBasedKeyDerivationParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Parameters prfParameters = parameters.getPrfParameters();
    if (prfParameters instanceof HkdfPrfParameters) {
      HkdfPrfKey prfKey =
          createHkdfPrfKey((HkdfPrfParameters) prfParameters, /* idRequirement= */ null);
      return PrfBasedKeyDerivationKey.create(parameters, prfKey, idRequirement);
    }
    throw new GeneralSecurityException("Unsupported PRF parameters: " + prfParameters.getClass());
  }
}
