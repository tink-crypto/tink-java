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

package com.google.crypto.tink.signature.internal.testing;

import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/**
 * Test vector for the ML-DSA external mu computation (FIPS 204, Algorithm 7, line 6) with an empty
 * context string: {@code mu = SHAKE256-512(SHAKE256-512(publicKeyBytes) || 0x00 || 0x00 ||
 * message)}.
 */
@Immutable
public final class MlDsaMuTestVector {
  private final MlDsaInstance instance;
  private final Bytes publicKeyBytes;
  private final Bytes message;
  private final Bytes mu;

  public MlDsaMuTestVector(
      MlDsaInstance instance, byte[] publicKeyBytes, byte[] message, byte[] mu) {
    this.instance = instance;
    this.publicKeyBytes = Bytes.copyFrom(publicKeyBytes);
    this.message = Bytes.copyFrom(message);
    this.mu = Bytes.copyFrom(mu);
  }

  public MlDsaInstance getInstance() {
    return instance;
  }

  /** The raw encoding of the ML-DSA public key. */
  public byte[] getPublicKeyBytes() {
    return publicKeyBytes.toByteArray();
  }

  public byte[] getMessage() {
    return message.toByteArray();
  }

  /** The 64-byte message representative of {@code message} under {@code publicKeyBytes}. */
  public byte[] getMu() {
    return mu.toByteArray();
  }

  @Override
  public String toString() {
    return String.format("MlDsaMuTestVector(%s, message=%s, mu=%s)", instance, message, mu);
  }
}
