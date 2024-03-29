// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.proto.Keyset.Key;
import java.security.GeneralSecurityException;

/**
 * Constants and convenience methods that deal with crypto format.
 *
 * @since 1.0.0
 */
public final class CryptoFormat {

  /** Prefix size of Tink, Legacy and Crunchy output prefix types. */
  public static final int NON_RAW_PREFIX_SIZE = OutputPrefixUtil.NON_EMPTY_PREFIX_SIZE;

  /** Legacy or Crunchy prefix starts with \x00 and followed by a 4-byte key id. */
  public static final int LEGACY_PREFIX_SIZE = OutputPrefixUtil.NON_EMPTY_PREFIX_SIZE;

  public static final byte LEGACY_START_BYTE = OutputPrefixUtil.LEGACY_START_BYTE;

  /** Tink prefix starts with \x01 and followed by a 4-byte key id. */
  public static final int TINK_PREFIX_SIZE = OutputPrefixUtil.NON_EMPTY_PREFIX_SIZE;

  public static final byte TINK_START_BYTE = OutputPrefixUtil.TINK_START_BYTE;

  /** Raw prefix is empty. */
  public static final int RAW_PREFIX_SIZE = 0;

  public static final byte[] RAW_PREFIX = new byte[0];

  /**
   * Generates the prefix of all cryptographic outputs (ciphertexts, signatures, MACs, ...) produced
   * by the specified {@code key}. The prefix can be either empty (for RAW-type prefix), or consists
   * of a 1-byte indicator of the type of the prefix, followed by 4 bytes of {@code key.key_id} in
   * Big Endian encoding.
   *
   * @throws GeneralSecurityException if the prefix type of {@code key} is unknown.
   * @return a prefix.
   */
  public static byte[] getOutputPrefix(Key key) throws GeneralSecurityException {
    switch (key.getOutputPrefixType()) {
      case LEGACY: // fall through
      case CRUNCHY:
        return OutputPrefixUtil.getLegacyOutputPrefix(key.getKeyId()).toByteArray();
      case TINK:
        return OutputPrefixUtil.getTinkOutputPrefix(key.getKeyId()).toByteArray();
      case RAW:
        return RAW_PREFIX;
      default:
        throw new GeneralSecurityException("unknown output prefix type");
    }
  }

  private CryptoFormat() {}
}
