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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.errorprone.annotations.Immutable;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Configuration for keys used with PRF-based key derivation.
 *
 * <p>PRF-based key derivation (implemented by {@link
 * com.google.crypto.tink.keyderivation.KeysetDeriver}) uses a PRF key (such as {@link
 * com.google.crypto.tink.prf.HkdfPrfKey}) to produce a stream of pseudorandom bytes from a salt,
 * and then derives a child key (such as {@link com.google.crypto.tink.aead.AesGcmKey} or {@link
 * com.google.crypto.tink.mac.HmacKey}) from that randomness stream.
 *
 * <p>A {@code PrfBasedKeyDerivationKeyConfig} encapsulates two aspects of key derivation:
 *
 * <ul>
 *   <li><b>Proto Serialization Configuration:</b> The {@link Configuration} returned by {@link
 *       #getConfiguration()} provides the serializers and parsers needed by {@link
 *       PrfBasedKeyDerivationKeyProtoSerialization} to serialize and parse the PRF key (e.g.,
 *       {@link com.google.crypto.tink.prf.HkdfPrfKey}) and the parameters of the derived keys
 *       (e.g., {@link com.google.crypto.tink.aead.AesGcmParameters}, {@link
 *       com.google.crypto.tink.mac.HmacParameters}).
 *   <li><b>Key-from-Randomness Derivation:</b> A registry of {@link
 *       PrfBasedKeyDerivationKeyConfigBuilder.KeyFromRandomness} factories used by {@link
 *       #createKeyFromRandomness} (and invoked by {@link PrfBasedKeyDeriver}) to instantiate a
 *       concrete {@link Key} from the pseudorandom randomness stream according to its {@link
 *       Parameters}.
 * </ul>
 *
 * <p>Instances of this class are immutable and are created using {@link
 * PrfBasedKeyDerivationKeyConfigBuilder}.
 */
@Immutable
public final class PrfBasedKeyDerivationKeyConfig {
  // Configuration is immutable.
  @SuppressWarnings("Immutable")
  private final Configuration configuration;

  // Map is unmodifiable and its values are immutable KeyFromRandomness instances.
  @SuppressWarnings("Immutable")
  private final Map<
          Class<? extends Parameters>, PrfBasedKeyDerivationKeyConfigBuilder.KeyFromRandomness<?>>
      keyFromRandomnessMap;

  PrfBasedKeyDerivationKeyConfig(
      Configuration configuration,
      Map<Class<? extends Parameters>, PrfBasedKeyDerivationKeyConfigBuilder.KeyFromRandomness<?>>
          keyFromRandomnessMap) {
    this.configuration = configuration;
    this.keyFromRandomnessMap = keyFromRandomnessMap;
  }

  /**
   * Returns the underlying {@link Configuration} containing the serializers and parsers for PRF
   * keys and derived key parameters.
   */
  public Configuration getConfiguration() {
    return configuration;
  }

  /**
   * Creates a {@link Key} from a pseudorandom stream according to the given {@link Parameters}.
   *
   * @param parameters the parameters specifying the key type and configuration to create
   * @param stream the input stream providing pseudorandom bytes (e.g. from a PRF)
   * @param idRequirement the required key ID, or null if the key has no prefix/requirement
   * @param access the secret key access token required to access key material
   * @return the derived {@link Key}
   * @throws GeneralSecurityException if no {@code KeyFromRandomness} factory is registered for
   *     {@code parameters.getClass()}, or if key creation fails
   */
  public Key createKeyFromRandomness(
      Parameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    // Safe because addKeyFromRandomness enforces type safety between the key and value.
    @SuppressWarnings("unchecked")
    PrfBasedKeyDerivationKeyConfigBuilder.KeyFromRandomness<Parameters> creator =
        (PrfBasedKeyDerivationKeyConfigBuilder.KeyFromRandomness<Parameters>)
            keyFromRandomnessMap.get(parameters.getClass());
    if (creator == null) {
      throw new GeneralSecurityException(
          "Cannot use key derivation to derive key for parameters "
              + parameters
              + ": unsupported parameters class");
    }
    return creator.createKeyFromRandomness(parameters, stream, idRequirement, access);
  }
}
