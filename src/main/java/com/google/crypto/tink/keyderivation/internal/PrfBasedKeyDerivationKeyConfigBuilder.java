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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Builder to create {@link PrfBasedKeyDerivationKeyConfig} instances.
 *
 * <p>PRF-based key derivation in Tink derives child keys (such as {@link
 * com.google.crypto.tink.aead.AesGcmKey}, {@link com.google.crypto.tink.mac.HmacKey}, {@link
 * com.google.crypto.tink.aead.AesCtrHmacAeadKey}, etc.) from pseudorandom bytes produced by a PRF
 * key (such as {@link com.google.crypto.tink.prf.HkdfPrfKey}).
 *
 * <p>This builder configures:
 *
 * <ul>
 *   <li><b>Serialization:</b> Proto serializers and parsers for the PRF keys (using {@link
 *       #addKeySerializer} and {@link #addKeyParser}) and for the parameters of keys that can be
 *       derived (using {@link #addParametersSerializer} and {@link #addParametersParser}).
 *   <li><b>Key Derivation:</b> Mapping from derived key {@link Parameters} classes to their {@link
 *       KeyFromRandomness} factories (using {@link #addKeyFromRandomness}), which read pseudorandom
 *       bytes from an {@link InputStream} and construct the derived {@link Key}.
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * PrfBasedKeyDerivationKeyConfig config =
 *     new PrfBasedKeyDerivationKeyConfigBuilder()
 *         // PRF key serialization
 *         .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
 *         .addKeyParser(
 *             "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
 *             HkdfPrfProtoSerialization::parseKey)
 *         .addParametersSerializer(
 *             HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
 *         .addParametersParser(
 *             "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
 *             HkdfPrfProtoSerialization::parseParameters)
 *         // Derived key parameters serialization
 *         .addParametersSerializer(
 *             AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
 *         .addParametersParser(
 *             "type.googleapis.com/google.crypto.tink.AesGcmKey",
 *             AesGcmProtoSerialization::parseParameters)
 *         // Derived key creation from randomness
 *         .addKeyFromRandomness(
 *             AesGcmParameters.class, AesGcmKey::createFromRandomness)
 *         .build();
 * }</pre>
 */
public final class PrfBasedKeyDerivationKeyConfigBuilder {

  /**
   * Functional interface to create a {@link Key} from a pseudorandom stream according to the given
   * {@link Parameters}.
   */
  @FunctionalInterface
  public interface KeyFromRandomness<P extends Parameters> {
    /**
     * Creates a key from the provided randomness stream.
     *
     * @param parameters parameters of the key to create
     * @param inputStream stream providing pseudorandom bytes
     * @param idRequirement ID requirement for the key, or null
     * @param access secret key access token
     * @return the derived {@link Key}
     * @throws GeneralSecurityException if key creation fails
     */
    Key createKeyFromRandomness(
        P parameters,
        InputStream inputStream,
        @Nullable Integer idRequirement,
        SecretKeyAccess access)
        throws GeneralSecurityException;
  }

  private final ProtoBasedConfigurationBuilder protoBasedConfigurationBuilder =
      new ProtoBasedConfigurationBuilder();
  private final Map<Class<? extends Parameters>, KeyFromRandomness<?>> keyFromRandomnessMap =
      new HashMap<>();

  public PrfBasedKeyDerivationKeyConfigBuilder() {}

  /**
   * Adds a serializer for the given {@link Key} class (typically a PRF key such as {@link
   * com.google.crypto.tink.prf.HkdfPrfKey}) to the configuration used for key derivation.
   */
  @CanIgnoreReturnValue
  public <K extends Key> PrfBasedKeyDerivationKeyConfigBuilder addKeySerializer(
      Class<K> keyClass, ProtoBasedConfigurationBuilder.KeySerializer<K> keySerializer) {
    protoBasedConfigurationBuilder.addKeySerializer(keyClass, keySerializer);
    return this;
  }

  /**
   * Adds a parser for the given {@link Key} type URL (typically a PRF key such as {@link
   * com.google.crypto.tink.prf.HkdfPrfKey}) to the configuration used for key derivation.
   */
  @CanIgnoreReturnValue
  public PrfBasedKeyDerivationKeyConfigBuilder addKeyParser(
      String typeUrl, ProtoBasedConfigurationBuilder.KeyParser keyParser) {
    protoBasedConfigurationBuilder.addKeyParser(typeUrl, keyParser);
    return this;
  }

  /**
   * Adds a serializer for the given {@link Parameters} class (for PRF parameters or derived key
   * parameters such as {@link com.google.crypto.tink.aead.AesGcmParameters}) to the configuration
   * used for key derivation.
   */
  @CanIgnoreReturnValue
  public <P extends Parameters> PrfBasedKeyDerivationKeyConfigBuilder addParametersSerializer(
      Class<P> parametersClass,
      ProtoBasedConfigurationBuilder.ParametersSerializer<P> parametersSerializer) {
    protoBasedConfigurationBuilder.addParametersSerializer(parametersClass, parametersSerializer);
    return this;
  }

  /**
   * Adds a parser for the given {@link Parameters} type URL (for PRF parameters or derived key
   * parameters such as {@link com.google.crypto.tink.aead.AesGcmParameters}) to the configuration
   * used for key derivation.
   */
  @CanIgnoreReturnValue
  public PrfBasedKeyDerivationKeyConfigBuilder addParametersParser(
      String typeUrl, ProtoBasedConfigurationBuilder.ParametersParser parametersParser) {
    protoBasedConfigurationBuilder.addParametersParser(typeUrl, parametersParser);
    return this;
  }

  /**
   * Adds a {@link KeyFromRandomness} factory for the given {@link Parameters} class used for
   * deriving keys from pseudorandom bytes.
   *
   * @param parametersClass the parameters class to register the factory for
   * @param keyFromRandomness the factory that constructs a key from randomness
   * @throws IllegalArgumentException if a factory for {@code parametersClass} is already registered
   */
  @CanIgnoreReturnValue
  public <P extends Parameters> PrfBasedKeyDerivationKeyConfigBuilder addKeyFromRandomness(
      Class<P> parametersClass, KeyFromRandomness<P> keyFromRandomness) {
    if (keyFromRandomnessMap.containsKey(parametersClass)) {
      throw new IllegalArgumentException(
          "KeyFromRandomness for " + parametersClass.getName() + " already exists");
    }
    keyFromRandomnessMap.put(parametersClass, keyFromRandomness);
    return this;
  }

  /** Builds and returns a new immutable {@link PrfBasedKeyDerivationKeyConfig}. */
  public PrfBasedKeyDerivationKeyConfig build() {
    return new PrfBasedKeyDerivationKeyConfig(
        protoBasedConfigurationBuilder.build(),
        Collections.unmodifiableMap(new HashMap<>(keyFromRandomnessMap)));
  }
}
