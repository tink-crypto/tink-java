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

import java.math.BigInteger;
import java.util.List;

/** Utility methods for ASN.1 encoding. */
public final class Asn1EncodingUtil {

  private Asn1EncodingUtil() {}

  /** ASN.1 encodes a BigInteger as an INTEGER. */
  public static byte[] createInteger(BigInteger val) {
    byte[] bytes = val.toByteArray();
    byte[] lengthField = createLength(bytes.length);
    byte[] result = new byte[1 + lengthField.length + bytes.length];

    result[0] = Asn1TagConstants.TAG_INTEGER;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    System.arraycopy(bytes, 0, result, 1 + lengthField.length, bytes.length);
    return result;
  }

  private static byte[] createLength(int length) {
    if (length <= 127) {
      return new byte[] {(byte) length};
    }

    int temp = length;
    int numBytes = 0;
    while (temp > 0) {
      numBytes++;
      temp >>= 8;
    }

    byte[] result = new byte[1 + numBytes];
    result[0] = (byte) (0x80 | numBytes);
    for (int i = numBytes; i > 0; i--) {
      result[i] = (byte) (length & 0xFF);
      length >>= 8;
    }
    return result;
  }

  /** ASN.1 encodes a list of DER encoded elements as a SEQUENCE. */
  public static byte[] createSequence(List<byte[]> elements) {
    int totalLength = 0;
    for (byte[] el : elements) {
      totalLength += el.length;
    }
    byte[] lengthField = createLength(totalLength);
    byte[] result = new byte[1 + lengthField.length + totalLength];

    result[0] = Asn1TagConstants.TAG_SEQUENCE;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    int offset = 1 + lengthField.length;
    for (byte[] el : elements) {
      System.arraycopy(el, 0, result, offset, el.length);
      offset += el.length;
    }
    return result;
  }

  /** ASN.1 encodes a byte array as an OCTET STRING. */
  public static byte[] createOctetString(byte[] value) {
    byte[] lengthField = createLength(value.length);
    byte[] result = new byte[1 + lengthField.length + value.length];
    result[0] = Asn1TagConstants.TAG_OCTET_STRING;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    System.arraycopy(value, 0, result, 1 + lengthField.length, value.length);
    return result;
  }
}
