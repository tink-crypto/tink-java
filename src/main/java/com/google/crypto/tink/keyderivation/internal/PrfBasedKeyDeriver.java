// Copyright 2023 Google LLC
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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.errorprone.annotations.Immutable;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Implements the KeyDeriver interface by first applying a Prf and then using a KeyFromRandomness
 * function to create the correct key.
 */
@Immutable
public final class PrfBasedKeyDeriver implements KeyDeriver {
  final StreamingPrf prf;
  final KeyFromRandomness keyFromRandomness;
  final PrfBasedKeyDerivationKey key;

  /** Functional interface to get a StreamingPrf from a Key. */
  @FunctionalInterface
  public interface PrfGetter {
    StreamingPrf get(Key key) throws GeneralSecurityException;
  }

  /** Functional interface to create a Key from randomness. */
  @FunctionalInterface
  @Immutable
  public interface KeyFromRandomness {
    Key createKeyFromRandomness(
        Parameters parameters,
        InputStream inputStream,
        @Nullable Integer idRequirement,
        SecretKeyAccess access)
        throws GeneralSecurityException;
  }

  private PrfBasedKeyDeriver(
      StreamingPrf prf, KeyFromRandomness keyFromRandomness, PrfBasedKeyDerivationKey key) {
    this.prf = prf;
    this.keyFromRandomness = keyFromRandomness;
    this.key = key;
  }

  @AccessesPartialKey
  public static KeyDeriver create(
      PrfGetter prfGetter, KeyFromRandomness keyFromRandomness, PrfBasedKeyDerivationKey key)
      throws GeneralSecurityException {
    StreamingPrf prf = prfGetter.get(key.getPrfKey());
    PrfBasedKeyDeriver deriver = new PrfBasedKeyDeriver(prf, keyFromRandomness, key);
    Object unused = deriver.deriveKey(new byte[] {1});
    return deriver;
  }

  @Override
  @AccessesPartialKey
  public Key deriveKey(byte[] salt) throws GeneralSecurityException {
    InputStream inputStream = prf.computePrf(salt);
    return keyFromRandomness.createKeyFromRandomness(
        key.getParameters().getDerivedKeyParameters(),
        inputStream,
        key.getIdRequirementOrNull(),
        InsecureSecretKeyAccess.get());
  }
}
