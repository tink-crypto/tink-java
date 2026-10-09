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
 * Interface for computing prehashes from raw message data.
 *
 * <p>This interface is intended to support the prehash-and-sign paradigm, such as in ML-DSA
 * External Mu mode.
 */
public interface Prehash {
  /** Computes the pre-hashed message representative for {@code data}. */
  byte[] compute(byte[] data) throws GeneralSecurityException;
}
