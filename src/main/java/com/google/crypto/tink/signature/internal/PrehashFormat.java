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

package com.google.crypto.tink.signature.internal;

import java.nio.ByteBuffer;

/**
 * Format utilities for prehash values, as computed by {@code Prehash} and signed by {@code
 * SignPrehash}.
 *
 * <p>A prehash value computed with a key with an ID requirement starts with a 5-byte prefix: the
 * byte {@code 0xff}, followed by the 4-byte big-endian key ID. Every prehash value has the same
 * prefix format, regardless of the key type. The prefix is followed by the key type specific
 * message representative (for example, the message representative mu for ML-DSA).
 */
public final class PrehashFormat {
  /** Prehash prefix starts with the 0xff byte. */
  public static final byte PREHASH_START_BYTE = (byte) 0xff;

  /** Prehash prefix has a start byte followed by a 4-byte key ID. */
  public static final int PREHASH_PREFIX_SIZE = 5;

  /**
   * Returns the prehash prefix {@code 0xff || idRequirement}, where {@code idRequirement} is
   * encoded in big-endian.
   */
  public static byte[] getPrehashPrefix(int idRequirement) {
    return ByteBuffer.allocate(PREHASH_PREFIX_SIZE) // BIG_ENDIAN by default
        .put(PREHASH_START_BYTE)
        .putInt(idRequirement)
        .array();
  }

  private PrehashFormat() {}
}
