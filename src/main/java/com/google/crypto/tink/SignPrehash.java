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

package com.google.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * Prehash signing interface for remote signing workflows.
 *
 * <p>This interface is intended to support the prehash-and-sign paradigm, such as in ML-DSA
 * External Mu mode.
 */
public interface SignPrehash {
  /** Computes the signature for {@code prehash}. */
  byte[] sign(byte[] prehash) throws GeneralSecurityException;
}
