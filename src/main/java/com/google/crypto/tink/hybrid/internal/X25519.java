// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/** Interface for X25519. */
@Immutable
public interface X25519 {

  /** Keypair. */
  public static final class KeyPair {
    public final byte[] privateKey;
    public final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  }

  /** generateKeyPair. */
  public KeyPair generateKeyPair() throws GeneralSecurityException;

  /** computeSharedSecret. */
  public byte[] computeSharedSecret(byte[] privateValue, byte[] peersPublicValue)
      throws GeneralSecurityException;
}
