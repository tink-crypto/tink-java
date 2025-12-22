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

package com.google.crypto.tink.internal;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

/** Provides secure randomness using {@link SecureRandom}. */
public final class Random {
  private static final ThreadLocal<SecureRandom> localRandom =
      new ThreadLocal<SecureRandom>() {
        @Override
        protected SecureRandom initialValue() {
          return newDefaultSecureRandom();
        }
      };

  private static SecureRandom create() {
    // Use Conscrypt if possible.
    // For legacy compatibility reasons it uses the algorithm name "SHA1PRNG".
    Provider conscryptProvider = ConscryptUtil.providerOrNull();
    if (conscryptProvider != null) {
      try {
        return SecureRandom.getInstance("SHA1PRNG", conscryptProvider);
      } catch (GeneralSecurityException e) {
        // ignore
      }
    }
    // TODO(b/470889007): Call ConscryptUtil.providerWithReflectionOrNull once this bug is fixed.
    return new SecureRandom();
  }

  private static SecureRandom newDefaultSecureRandom() {
    SecureRandom retval = create();
    retval.nextLong(); // force seeding
    return retval;
  }

  /** Returns a random byte array of size {@code size}. */
  public static byte[] randBytes(int size) {
    byte[] rand = new byte[size];
    localRandom.get().nextBytes(rand);
    return rand;
  }

  public static final int randInt(int max) {
    return localRandom.get().nextInt(max);
  }

  public static final int randInt() {
    return localRandom.get().nextInt();
  }

  /** Throws a GeneralSecurityException if the provider is not Conscrypt. */
  public static final void validateUsesConscrypt() throws GeneralSecurityException {
    if (!ConscryptUtil.isConscryptProvider(localRandom.get().getProvider())) {
      throw new GeneralSecurityException(
          "Requires GmsCore_OpenSSL, AndroidOpenSSL or Conscrypt to generate randomness, but got "
              + localRandom.get().getProvider().getName());
    }
  }

  private Random() {}
}
