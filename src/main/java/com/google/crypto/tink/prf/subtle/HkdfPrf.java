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

package com.google.crypto.tink.prf.subtle;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/** Direct interface to HKDF PRF primitives. */
public final class HkdfPrf {
  private HkdfPrf() {}

  /** Creates a Prf from a given {@link HkdfPrfKey}. */
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static Prf create(HkdfPrfKey key) throws GeneralSecurityException {
    return PrfImpl.wrap(HkdfStreamingPrf.create(key));
  }
}
