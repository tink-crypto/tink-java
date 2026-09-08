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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.subtle.Hex;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Asn1Util}.
 *
 * <p>Verifies ASN.1 DER encoding operations against hardcoded expected byte arrays and hex strings.
 */
@RunWith(JUnit4.class)
public final class Asn1UtilTest {

  @Test
  public void createInteger_encodesCorrectly() {
    assertThat(Hex.encode(Asn1Util.createInteger(BigInteger.ZERO))).isEqualTo("020100");
    assertThat(Hex.encode(Asn1Util.createInteger(BigInteger.ONE))).isEqualTo("020101");
    assertThat(Hex.encode(Asn1Util.createInteger(BigInteger.valueOf(127)))).isEqualTo("02017f");
    // Positive 128 requires leading 0x00 to avoid being interpreted as negative
    assertThat(Hex.encode(Asn1Util.createInteger(BigInteger.valueOf(128)))).isEqualTo("02020080");
    assertThat(Hex.encode(Asn1Util.createInteger(BigInteger.valueOf(256)))).isEqualTo("02020100");
  }

  @Test
  public void createOctetString_encodesCorrectly() {
    assertThat(Hex.encode(Asn1Util.createOctetString(new byte[0]))).isEqualTo("0400");
    byte[] input = new byte[] {0x01, 0x02, 0x03};
    assertThat(Hex.encode(Asn1Util.createOctetString(input))).isEqualTo("0403010203");

    // Test length > 127 bytes (long form length encoding)
    byte[] longInput = new byte[130];
    byte[] encodedLong = Asn1Util.createOctetString(longInput);
    // 0x04 (TAG_OCTET_STRING), 0x81 (long length: 1 byte follows), 0x82 (130)
    assertThat(encodedLong[0]).isEqualTo((byte) 0x04);
    assertThat(encodedLong[1]).isEqualTo((byte) 0x81);
    assertThat(encodedLong[2]).isEqualTo((byte) 0x82);
    assertThat(encodedLong).hasLength(1 + 2 + 130);
  }

  @Test
  public void createSequence_encodesCorrectly() {
    // Empty sequence
    assertThat(Hex.encode(Asn1Util.createSequence(Collections.emptyList()))).isEqualTo("3000");

    // Sequence with elements
    byte[] intElem = Asn1Util.createInteger(BigInteger.ONE);
    byte[] octetElem = Asn1Util.createOctetString(new byte[] {0x01, 0x02});
    assertThat(Hex.encode(Asn1Util.createSequence(Arrays.asList(intElem, octetElem))))
        .isEqualTo("300702010104020102");

    // Sequence with length > 127 bytes
    byte[] longElem = new byte[130];
    byte[] encodedSeq = Asn1Util.createSequence(Collections.singletonList(longElem));
    assertThat(encodedSeq[0]).isEqualTo((byte) 0x30);
    assertThat(encodedSeq[1]).isEqualTo((byte) 0x81);
    assertThat(encodedSeq[2]).isEqualTo((byte) 0x82);
    assertThat(encodedSeq).hasLength(1 + 2 + 130);
  }
}
