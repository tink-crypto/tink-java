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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
import java.math.BigInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Asn1StatefulParserTest {

  @Test
  public void parseInteger_singleByte_works() throws Exception {
    byte[] data = Hex.decode("020105");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    }
  }

  @Test
  public void parseInteger_zero_works() throws Exception {
    byte[] data = Hex.decode("020100");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.ZERO);
    }
  }

  @Test
  public void parseInteger_multiByte_works() throws Exception {
    byte[] data = Hex.decode("0203010001");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(65537));
    }
  }

  @Test
  public void parseTwoIntegers_works() throws Exception {
    byte[] data = Hex.decode("02010502010a");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(10));
    }
  }

  @Test
  public void parseNegativeInteger_works() throws Exception {
    byte[] data = Hex.decode("0201ff");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(-1));
    }
  }

  @Test  public void parseLongFormLength_works() throws Exception {
    // 0x02 (tag INTEGER), 0x81 (long form, 1 byte length), 0x80 (length 128)
    byte[] header = Hex.decode("028180");
    byte[] payload = new byte[128];
    payload[0] = 0x01;
    byte[] data = new byte[header.length + payload.length];
    System.arraycopy(header, 0, data, 0, header.length);
    System.arraycopy(payload, 0, data, header.length, payload.length);

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      BigInteger expected = BigInteger.ONE.shiftLeft(127 * 8);
      assertThat(parser.consumeInteger()).isEqualTo(expected);
    }
  }

  @Test
  public void parseLongFormLength_twoLengthBytes_works() throws Exception {
    // 0x02 (tag INTEGER), 0x82 (long form, 2 bytes length), 0x0100 (length 256)
    byte[] header = Hex.decode("02820100");
    byte[] payload = new byte[256];
    payload[0] = 0x01;
    byte[] data = new byte[header.length + payload.length];
    System.arraycopy(header, 0, data, 0, header.length);
    System.arraycopy(payload, 0, data, header.length, payload.length);

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      BigInteger expected = BigInteger.ONE.shiftLeft(255 * 8);
      assertThat(parser.consumeInteger()).isEqualTo(expected);
    }
  }

  @Test
  public void parseSequence_ofIntegers_works() throws Exception {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    byte[] data = Hex.decode("3006020101020102");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data);
        Asn1StatefulParser seqParser = parser.consumeSequence()) {
      assertThat(seqParser.consumeInteger()).isEqualTo(BigInteger.valueOf(1));
      assertThat(seqParser.consumeInteger()).isEqualTo(BigInteger.valueOf(2));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseSequence_lengthTooLong_throws() throws Exception {
    byte[] data = Hex.decode("3007020101020102");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeSequence);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseSequence_notAllInnerBytesConsumed_innerParserThrows() throws Exception {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    byte[] data = Hex.decode("30080201010201020000");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    Asn1StatefulParser seqParser = parser.consumeSequence();

    assertThat(seqParser.consumeInteger()).isEqualTo(BigInteger.valueOf(1));
    assertThat(seqParser.consumeInteger()).isEqualTo(BigInteger.valueOf(2));
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, seqParser::close);
    parser.close();
  }

  @Test
  public void parseOctetString_works() throws Exception {
    byte[] data = Hex.decode("040401020304");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeOctetString()).isEqualTo(Hex.decode("01020304"));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseOctetString_lengthTooLong_throws() throws Exception {
    byte[] data = Hex.decode("040501020304");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeOctetString);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  public void parseBitString_works() throws Exception {
    // BIT STRING with 0 unused bits
    byte[] data = Hex.decode("03050001020304");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeBitString()).isEqualTo(Hex.decode("01020304"));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseBitString_zeroLength_throws() throws Exception {
    byte[] data = Hex.decode("0300");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeBitString);
    parser.close(); // works here due to short payload
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseBitString_nonZeroUnusedBits_throws() throws Exception {
    byte[] data = Hex.decode("03020100");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeBitString);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void parseBitString_lengthTooLong_throws() throws Exception {
    byte[] data = Hex.decode("03050100");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeBitString);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void tagMismatch_throws() {
    byte[] data = Hex.decode("300b0609608648016503040311");
    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void truncatedData_throws() {
    byte[] data = Hex.decode("02050102");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void zeroLengthInteger_throws() throws Exception {
    byte[] data = Hex.decode("0200");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
    parser.close(); // works here due to short payload
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void nonMinimalInteger_redundantLeadingZero_throws() {
    // INTEGER with leading 0x00 when next byte is 0x05 (< 0x80)
    byte[] data = Hex.decode("02020005");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void indefiniteLength_throws() {
    // Indefinite length 0x80
    byte[] data = Hex.decode("02800201010000");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() will throw.
  public void nonMinimalLengthEncoding_throws() {
    // Length 1 encoded in long form 0x8101
    byte[] data = Hex.decode("02810105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeInteger);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  public void tryWithResources_successfulParsing() throws Exception {
    byte[] data = Hex.decode("020105");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed") // Cannot use try-with-resources because close() throws.
  public void tryWithResources_unconsumedBytes_throwsOnClose() throws Exception {
    byte[] data = Hex.decode("02010500");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void close_isIdempotent() throws Exception {
    byte[] data = Hex.decode("020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    parser.close();
    parser.close();
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void operationsAfterClose_throwIllegalStateException() throws Exception {
    byte[] data = Hex.decode("020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);

    assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    parser.close();
    assertThrows(IllegalStateException.class, parser::consumeInteger);
  }
  @Test
  public void peekTag_works() throws Exception {
    byte[] data = Hex.decode("02010504020102");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.peekTag()).isEqualTo((byte) 0x02);
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));

      assertThat(parser.peekTag()).isEqualTo((byte) 0x04);
      assertThat(parser.consumeOctetString()).isEqualTo(Hex.decode("0102"));

      assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::peekTag);
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void peekTag_afterClose_throws() throws Exception {
    byte[] data = Hex.decode("020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    parser.close();
    assertThrows(IllegalStateException.class, parser::peekTag);
  }

  @Test
  public void consumeTaggedBytes_works() throws Exception {
    // [0] EXPLICIT { INTEGER 5, OCTET STRING 0102 }: a0 07 02 01 05 04 02 01 02
    byte[] data = Hex.decode("a00702010504020102");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data);
        Asn1StatefulParser taggedParser = parser.consumeTaggedBytes((byte) 0xa0)) {
      assertThat(taggedParser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
      assertThat(taggedParser.consumeOctetString()).isEqualTo(Hex.decode("0102"));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeTaggedBytes_wrongTag_throws() throws Exception {
    byte[] data = Hex.decode("a003020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThrows(
        Asn1StatefulParser.Asn1ParserException.class, () -> parser.consumeTaggedBytes((byte) 0xa1));
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeTaggedBytes_lengthTooLong_throws() throws Exception {
    // Length 0x05 declared, but only 3 bytes of payload provided: a0 05 02 01 05
    byte[] data = Hex.decode("a005020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThrows(
        Asn1StatefulParser.Asn1ParserException.class, () -> parser.consumeTaggedBytes((byte) 0xa0));
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeTaggedBytes_afterClose_throws() throws Exception {
    byte[] data = Hex.decode("a003020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    try (Asn1StatefulParser taggedParser = parser.consumeTaggedBytes((byte) 0xa0)) {
      assertThat(taggedParser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    }
    parser.close();
    assertThrows(IllegalStateException.class, () -> parser.consumeTaggedBytes((byte) 0xa0));
  }

  @Test
  public void consumeOid_works() throws Exception {
    // OBJECT IDENTIFIER 1.2.840.10045.3.1.7 (NIST P-256): 06 08 2a 86 48 ce 3d 03 01 07
    byte[] data = Hex.decode("06082a8648ce3d030107");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.consumeOid()).isEqualTo(Hex.decode("2a8648ce3d030107"));
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeOid_wrongTag_throws() throws Exception {
    byte[] data = Hex.decode("04082a8648ce3d030107");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeOid);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeOid_lengthTooLong_throws() throws Exception {
    // Length 9 declared, but only 8 bytes provided: 06 09 2a 86 48 ce 3d 03 01 07
    byte[] data = Hex.decode("06092a8648ce3d030107");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::consumeOid);
    assertThrows(Asn1StatefulParser.Asn1ParserException.class, parser::close);
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void consumeOid_afterClose_throws() throws Exception {
    byte[] data = Hex.decode("06082a8648ce3d030107");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThat(parser.consumeOid()).isEqualTo(Hex.decode("2a8648ce3d030107"));
    parser.close();
    assertThrows(IllegalStateException.class, parser::consumeOid);
  }

  @Test
  public void hasRemaining_works() throws Exception {
    byte[] data = Hex.decode("02010504020102");

    try (Asn1StatefulParser parser = new Asn1StatefulParser(data)) {
      assertThat(parser.hasRemaining()).isTrue();
      assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
      assertThat(parser.hasRemaining()).isTrue();
      assertThat(parser.consumeOctetString()).isEqualTo(Hex.decode("0102"));
      assertThat(parser.hasRemaining()).isFalse();
    }
  }

  @Test
  @SuppressWarnings("MustBeClosed")
  public void hasRemaining_afterClose_throws() throws Exception {
    byte[] data = Hex.decode("020105");

    Asn1StatefulParser parser = new Asn1StatefulParser(data);
    assertThat(parser.consumeInteger()).isEqualTo(BigInteger.valueOf(5));
    parser.close();
    assertThrows(IllegalStateException.class, parser::hasRemaining);
  }
}
