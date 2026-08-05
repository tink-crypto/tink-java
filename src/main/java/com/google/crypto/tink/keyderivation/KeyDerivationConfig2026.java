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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.Configuration;
import java.security.GeneralSecurityException;

/**
 * KeyDerivationConfig2026 contains the following primitives and algorithms for {@link
 * KeysetDeriver}:
 *
 * <ul>
 *   <li>HKDF-PRF-based key derivation
 * </ul>
 */
public class KeyDerivationConfig2026 {
  private KeyDerivationConfig2026() {}

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    return com.google.crypto.tink.keyderivation.internal.KeyDerivationConfig2026.get();
  }
}
