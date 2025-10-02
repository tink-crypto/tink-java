// Copyright 2025 Google LLC
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

import com.google.crypto.tink.DeterministicAead;
import java.security.GeneralSecurityException;

/**
 * Interface for Deterministic Authenticated Encryption with multiple Associated Datas
 *
 * <p>This interface is a generalization of {@link DeterministicAead}: DeterministicAead requires
 * exactly one associated data, while DeterministicAeads allows a list of associated datas. If the
 * list has size 1, the behavior must be exactly the same the methods of {@link DeterministicAead}.
 *
 * <p>For why this interface is desirable and some of its use cases, see for example <a
 * href="https://tools.ietf.org/html/rfc5297#section-1.3">RFC 5297 section 1.3</a>.
 *
 * <h3>Warning</h3>
 *
 * <p>Unlike {@link Aead}, implementations of this interface are not semantically secure, because
 * encrypting the same plaintext always yields the same ciphertext.
 */
public interface DeterministicAeads extends DeterministicAead {

  /** Deterministically encrypts {@code plaintext} with a list of associated authenticated data. */
  byte[] encryptDeterministically(final byte[] plaintext, final byte[]... associatedDatas)
      throws GeneralSecurityException;

  /** Deterministically decrypts {@code ciphertext} with a list of associated authenticated data. */
  byte[] decryptDeterministically(final byte[] ciphertext, final byte[]... associatedDatas)
      throws GeneralSecurityException;
}
