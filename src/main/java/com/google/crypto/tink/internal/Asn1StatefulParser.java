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

package com.google.crypto.tink.internal;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.MustBeClosed;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A stateful ASN.1 DER parser that keeps track of the current reading offset.
 * It follows the ASN.1 specification in ITU-T X.680
 * (https://www.itu.int/rec/T-REC-X.680-202102-I/en) and the DER encoding rules in ITU-T X.690
 * (https://www.itu.int/rec/T-REC-X.690-202102-I/en).
 */
public final class Asn1StatefulParser implements AutoCloseable {
  private static final byte TAG_INTEGER = 0x02;

  /**
   * Exception thrown when ASN.1 DER parsing fails.
   *
   * We don't want to leak the stack trace in case an exception is thrown, as it might leak
   * information about key material which is being parsed. Hence, we want code using
   * Asn1StatefulParser to throw a new exception, and hence we make this exception internal to the
   * parser.
   */
  public static class Asn1ParserException extends Exception {
    public Asn1ParserException(String message) {
      super(message);
    }

    public Asn1ParserException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private final byte[] data;
  private int offset;
  private final int limit;
  private boolean closed;

  @MustBeClosed
  public Asn1StatefulParser(byte[] data) {
    this.data = data;
    this.offset = 0;
    this.limit = data.length;
    this.closed = false;
  }

  private void checkNotClosed() {
    if (closed) {
      throw new IllegalStateException("Parser is closed");
    }
  }

  private boolean hasRemaining() {
    return offset < limit;
  }

  /**
   * Closes this parser and asserts that all bytes have been consumed.
   *
   * @throws Asn1ParserException if there are unconsumed trailing bytes.
   */
  @Override
  public void close() throws Asn1ParserException {
    if (closed) {
      return;
    }
    closed = true;
    if (hasRemaining()) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
  }

  /**
   * Consumes an ASN.1 DER INTEGER and returns it as a {@link BigInteger}.
   *
   * @throws Asn1ParserException if the tag is not INTEGER or DER encoding is invalid.
   * @throws IllegalStateException if this parser is closed.
   */
  @CanIgnoreReturnValue
  public BigInteger consumeInteger() throws Asn1ParserException {
    checkNotClosed();
    int length = consumeTagAndLength(TAG_INTEGER);
    if (length == 0) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
    // Check minimal DER encoding for INTEGER:
    // If length > 1, the first 9 bits must not be all 0s or all 1s (no redundant leading byte).
    if (length > 1) {
      byte firstByte = data[offset];
      byte secondByte = data[offset + 1];
      if (firstByte == 0 && (secondByte & 0x80) == 0) {
        throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
      }
      if (firstByte == (byte) 0xFF && (secondByte & 0x80) != 0) {
        throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
      }
    }
    byte[] intBytes = Arrays.copyOfRange(data, offset, offset + length);
    offset += length;
    return new BigInteger(intBytes);
  }

  private int consumeTagAndLength(byte expectedTag) throws Asn1ParserException {
    byte tag = (byte) consumeByte();
    if (tag != expectedTag) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
    return consumeLength();
  }

  private int consumeLength() throws Asn1ParserException {
    int initialByte = consumeByte();
    if ((initialByte & 0x80) == 0) {
      // Short form length (0..127)
      if (offset + initialByte > limit) {
        throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
      }
      return initialByte;
    }

    // Long form length
    int numLengthBytes = initialByte & 0x7F;
    if (numLengthBytes == 0) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
    // While technically the valid length can be up to 127 bytes long, we only support up to 4
    // bytes since this encodes a length that is longer than any reasonable ASN.1 payload we expect
    // to parse at the moment.
    if (numLengthBytes > 4) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
    if (offset + numLengthBytes > limit) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }

    int length = 0;
    for (int i = 0; i < numLengthBytes; i++) {
      int nextByte = consumeByte();
      if (i == 0 && nextByte == 0) {
        throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
      }
      length = (length << 8) | nextByte;
    }

    if (length < 128 || length < 0 || offset + length > limit) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }

    return length;
  }

  private int consumeByte() throws Asn1ParserException {
    if (offset >= limit) {
      throw new Asn1ParserException("Failed to parse ASN.1 DER encoded key");
    }
    return data[offset++] & 0xFF;
  }
}
