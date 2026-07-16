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

package com.google.crypto.tink.daead.subtle;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Provides an implementation of {@link DeterministicAeads} from an {@link AesSivKey}.
 *
 * <p>Historical note: this should be preferred over the similar class in {@link
 * com.google.crypto.tink.subtle.AesSiv}: we plan to standardize the API surface for primitives from
 * single keys with classes in {@code com.google.crypto.tink.<primitive>.subtle.ClassName}.
 */
public final class AesSivDeterministicAead {

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static DeterministicAeads create(AesSivKey key) throws GeneralSecurityException {
    return AesSiv.create(key);
  }

  private AesSivDeterministicAead() {}
}
