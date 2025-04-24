// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Arrays;

/** Internal utility methods for {X}ChaCha20 implementations. */
final class ChaCha20Util {
  static final int BLOCK_SIZE_IN_INTS = 16;
  static final int KEY_SIZE_IN_INTS = 8;
  static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  // First four words of the initial state (in little-endian order):
  // 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
  // See also https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
  private static final int[] sigma =
      toIntArray(
          new byte[] {
            'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
          });

  /**
   * Sets the first 12 words of the initial state as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
   */
  static void setSigmaAndKey(int[] state, final int[] key) {
    System.arraycopy(sigma, 0, state, 0, sigma.length); // 4 words
    System.arraycopy(key, 0, state, sigma.length, KEY_SIZE_IN_INTS); // 8 words
  }

  /**
   * Computes the 20 ChaCha rounds as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
   */
  static void shuffleState(final int[] state) {
    for (int i = 0; i < 10; i++) {
      quarterRound(state, 0, 4, 8, 12);
      quarterRound(state, 1, 5, 9, 13);
      quarterRound(state, 2, 6, 10, 14);
      quarterRound(state, 3, 7, 11, 15);
      quarterRound(state, 0, 5, 10, 15);
      quarterRound(state, 1, 6, 11, 12);
      quarterRound(state, 2, 7, 8, 13);
      quarterRound(state, 3, 4, 9, 14);
    }
  }

  /**
   * Computes the ChaCha quarter round as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.1.
   */
  static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = rotateLeft(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotateLeft(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotateLeft(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotateLeft(x[b] ^ x[c], 7);
  }

  /** Converts {@code input} byte array to an int array */
  static int[] toIntArray(final byte[] input) {
    if (input.length % 4 != 0) {
      throw new IllegalArgumentException("invalid input length");
    }
    IntBuffer intBuffer = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
    int[] ret = new int[intBuffer.remaining()];
    intBuffer.get(ret);
    return ret;
  }

  static byte[] toByteArray(final int[] input) {
    ByteBuffer byteBuffer = ByteBuffer.allocate(input.length * 4).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.asIntBuffer().put(input);
    return byteBuffer.array();
  }

  // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.
  static int[] hChaCha20(final int[] key, final int[] nonce) {
    int[] state = new int[BLOCK_SIZE_IN_INTS];
    setSigmaAndKey(state, key);
    state[12] = nonce[0];
    state[13] = nonce[1];
    state[14] = nonce[2];
    state[15] = nonce[3];
    shuffleState(state);
    // state[0] = state[0], state[1] = state[1], state[2] = state[2], state[3] = state[3]
    state[4] = state[12];
    state[5] = state[13];
    state[6] = state[14];
    state[7] = state[15];
    return Arrays.copyOf(state, ChaCha20Util.KEY_SIZE_IN_INTS);
  }

  static byte[] hChaCha20(final byte[] key, final byte[] nonce) {
    return toByteArray(hChaCha20(toIntArray(key), toIntArray(nonce)));
  }

  private static int rotateLeft(int x, int y) {
    return (x << y) | (x >>> -y);
  }

  private ChaCha20Util() {}
}
