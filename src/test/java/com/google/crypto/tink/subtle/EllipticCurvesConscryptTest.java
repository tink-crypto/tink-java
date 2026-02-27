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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * Unit tests for {@link com.google.crypto.tink.subtle.EllipticCurves}, when Conscrypt is installed
 * as the default security provider.
 */
@RunWith(Theories.class)
public class EllipticCurvesConscryptTest {
  // The tests are from
  // http://google.github.io/end-to-end/api/source/src/javascript/crypto/e2e/ecc/ecdh_testdata.js.src.html.

  @Before
  public void setUpConscrypt() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.insertProviderAt(Conscrypt.newProvider(), 1);
    }
  }

  /**
   * A class for storing test vectors. This class contains the directory for the public and private
   * key, the message and the corresponding signature.
   */
  protected static class TestVector2 {
    protected EllipticCurves.CurveType curve;
    protected EllipticCurves.PointFormatType format;
    protected byte[] encoded;
    BigInteger x;
    BigInteger y;

    protected TestVector2(
        EllipticCurves.CurveType curve,
        EllipticCurves.PointFormatType format,
        String encodedHex,
        String x,
        String y) {
      this.curve = curve;
      this.format = format;
      this.encoded = Hex.decode(encodedHex);
      this.x = new BigInteger(x);
      this.y = new BigInteger(y);
    }
  }

  protected static final TestVector2[] testVectors2 = {
    // NIST_P256
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    // Exceptional point: x==0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "020000000000000000000000000000000000000000000000000000000000000000",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    // Exceptional point: x==-3
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
            + "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
            + "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    // NIST_P384
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc"
            + "29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e"
            + "5f",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab7",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    // x = 0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000003cf99ef04f51a5ea630ba3f9f960dd"
            + "593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e52"
            + "1e",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    // x = 2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002732152442fb6ee5c3e6ce1d920c059"
            + "bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfd"
            + "b3",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    // x = -3
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc2de9de09a95b74e6b2c430363e1afb"
            + "8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c"
            + "17",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    // NIST_P521
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b"
            + "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2"
            + "e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd"
            + "17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94"
            + "769fd16650",
        "2661740802050217063228768716723360960729859168756973147706671368"
            + "4188029449964278084915450806277719023520942412250655586621571135"
            + "45570916814161637315895999846",
        "3757180025770020463545507224491183603594455134769762486694567779"
            + "6155444774405563166912344050129455395621444445372894285225856667"
            + "29196580810124344277578376784"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b"
            + "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2"
            + "e5bd66",
        "2661740802050217063228768716723360960729859168756973147706671368"
            + "4188029449964278084915450806277719023520942412250655586621571135"
            + "45570916814161637315895999846",
        "3757180025770020463545507224491183603594455134769762486694567779"
            + "6155444774405563166912344050129455395621444445372894285225856667"
            + "29196580810124344277578376784"),
    // x = 0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896f"
            + "ee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440"
            + "ae001f4f87",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000000",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    // x = 1
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d"
            + "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c"
            + "832e843564",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000001",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    // x = 2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000200d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7f"
            + "ce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051"
            + "d6aa505acf",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000002",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    // x = -2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0401ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "fffffd0010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d"
            + "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c"
            + "832e843564",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "1855431833976560521225596406614545549772963113914808580371219879"
            + "99716643812574028291115057149",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "fffffd",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "1855431833976560521225596406614545549772963113914808580371219879"
            + "99716643812574028291115057149",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
  };

  @Test
  public void testFieldSizeInBytes() throws Exception {
    assertThat(
            EllipticCurves.fieldSizeInBytes(
                EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P256).getCurve()))
        .isEqualTo(32);
    assertThat(
            EllipticCurves.fieldSizeInBytes(
                EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P384).getCurve()))
        .isEqualTo(48);
    assertThat(
            EllipticCurves.fieldSizeInBytes(
                EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P521).getCurve()))
        .isEqualTo(66);
  }

  @Test
  public void testPointDecode() throws Exception {
    for (TestVector2 test : testVectors2) {
      EllipticCurve curve = EllipticCurves.getCurveSpec(test.curve).getCurve();
      ECPoint p = EllipticCurves.pointDecode(curve, test.format, test.encoded);
      assertEquals(p.getAffineX(), test.x);
      assertEquals(p.getAffineY(), test.y);
    }
  }

  @Test
  public void testPointEncode() throws Exception {
    for (TestVector2 test : testVectors2) {
      EllipticCurve curve = EllipticCurves.getCurveSpec(test.curve).getCurve();
      ECPoint p = new ECPoint(test.x, test.y);
      byte[] encoded = EllipticCurves.pointEncode(curve, test.format, p);
      assertEquals(Hex.encode(encoded), Hex.encode(test.encoded));
    }
  }

  @Test
  public void pointEncode_failsIfPointIsNotOnCurve() throws Exception {
    // Same an entry of testVectors2, but the value of y has been incremented by 1.
    BigInteger x = new BigInteger(
        "79974177209371530366349631093481213364328002500948308276357601809416549347930");
    BigInteger y = new BigInteger(
           "11093679777528052772423074391650378811758820120351664471899251711300542565880");
    // Adding one to y make the point not be on the curve.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EllipticCurves.pointEncode(
                EllipticCurves.CurveType.NIST_P256,
                EllipticCurves.PointFormatType.UNCOMPRESSED,
                new ECPoint(x, y)));
  }

  @Test
  public void pointDecode_uncompressed_failsIfPointIsNotOnCurve() throws Exception {
    // Same an entry of testVectors2, but the last byte is changed from f7 to f6
    byte[] encoded =
        Hex.decode(
            "04"
                + "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
                + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df6");
    // Adding one to y make the point not be on the curve.
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED, encoded));
  }

  @Test
  public void pointDecode_crunchy_failsIfPointIsNotOnCurve() throws Exception {
    // Same as an entry of testVectors2, but the last byte is changed from f4 to f5
    byte[] encoded =
        Hex.decode(
            "0000000000000000000000000000000000000000000000000000000000000000"
                + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f5");
    // Adding one to y make the point not be on the curve.
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED, encoded));
  }

  @Test
  public void pointDecode_compressed_failsIfEncodingIsInvalid() throws Exception {
    // Same as an entry of testVectors2, but the last byte is changed from 00 to 01
    byte[] encoded =
        Hex.decode("020000000000000000000000000000000000000000000000000000000000000001");
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.COMPRESSED, encoded));
  }

  /** A class to store a pair of valid Ecdsa signature in IEEE_P1363 and DER format. */
  protected static class EcdsaIeeeDer {
    public String hexIeee;
    public String hexDer;

    protected EcdsaIeeeDer(String hexIeee, String hexDer) {
      this.hexIeee = hexIeee;
      this.hexDer = hexDer;
    }
  };

  protected static final EcdsaIeeeDer[] ieeeDerTestVector =
      new EcdsaIeeeDer[] {
        new EcdsaIeeeDer( // normal case, short-form length
            "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10",
            "302402100102030405060708090a0b0c0d0e0f1002100102030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // normal case, long-form length
            "010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203",
            "30818802420100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000002030242010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203"),
        new EcdsaIeeeDer( // zero prefix.
            "0002030405060708090a0b0c0d0e0f100002030405060708090a0b0c0d0e0f10",
            "3022020f02030405060708090a0b0c0d0e0f10020f02030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // highest bit is set.
            "00ff030405060708090a0b0c0d0e0f1000ff030405060708090a0b0c0d0e0f10",
            "3024021000ff030405060708090a0b0c0d0e0f10021000ff030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // highest bit is set, full length.
            "ff02030405060708090a0b0c0d0e0f10ff02030405060708090a0b0c0d0e0f10",
            "3026021100ff02030405060708090a0b0c0d0e0f10021100ff02030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // all zeros.
            "0000000000000000000000000000000000000000000000000000000000000000", "3006020100020100"),
      };

  @Test
  public void testEcdsaIeee2Der() throws Exception {
    for (EcdsaIeeeDer test : ieeeDerTestVector) {
      assertArrayEquals(
          Hex.decode(test.hexDer), EllipticCurves.ecdsaIeee2Der(Hex.decode(test.hexIeee)));
    }
  }

  @Test
  public void testEcdsaDer2Ieee() throws Exception {
    for (EcdsaIeeeDer test : ieeeDerTestVector) {
      assertArrayEquals(
          Hex.decode(test.hexIeee),
          EllipticCurves.ecdsaDer2Ieee(Hex.decode(test.hexDer), test.hexIeee.length() / 2));
    }
  }

  protected static final String[] invalidEcdsaDers =
      new String[] {
        "2006020101020101", // 1st byte is not 0x30 (SEQUENCE tag)
        "3006050101020101", // 3rd byte is not 0x02 (INTEGER tag)
        "3006020101050101", // 6th byte is not 0x02 (INTEGER tag)
        "308206020101020101", // long form length is not 0x81
        "30ff020101020101", // invalid total length
        "3006020201020101", // invalid rLength
        "3006020101020201", // invalid sLength
        "30060201ff020101", // no extra zero when highest bit of r is set
        "30060201010201ff", // no extra zero when highest bit of s is set
      };

  @Test
  public void testIsValidDerEncoding() throws Exception {
    for (String der : invalidEcdsaDers) {
      assertFalse(EllipticCurves.isValidDerEncoding(Hex.decode(der)));
    }
  }

  @DataPoints("wycheproofTestVectorsPaths")
  public static final String[] wycheproofTestVectorPaths =
      new String[] {
        "third_party/wycheproof/testvectors_v1/ecdh_secp256r1_test.json",
        "third_party/wycheproof/testvectors_v1/ecdh_secp384r1_test.json",
        "third_party/wycheproof/testvectors_v1/ecdh_secp521r1_test.json",
      };

  @Theory
  public void testComputeSharedSecretWithWycheproofTestVectors(
      @FromDataPoints("wycheproofTestVectorsPaths") String path) throws Exception {
    if (TestUtil.isTsan()) {
      return;
    }

    JsonObject json = WycheproofTestUtil.readJson(path);
    ArrayList<String> errors = new ArrayList<>();
    ArrayList<String> warnings = new ArrayList<>();

    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.get("tests").getAsJsonArray();
      String curve = group.get("curve").getAsString();
      if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
        // Only NIST curves P-256, P-384 and P-521 are supported.
        continue;
      }
      EllipticCurves.CurveType curveType = WycheproofTestUtil.getCurveType(curve);
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        String result = testcase.get("result").getAsString();
        String hexPubKey = testcase.get("public").getAsString();
        String expectedSharedSecret = testcase.get("shared").getAsString();
        String hexPrivKey = testcase.get("private").getAsString();
        if (hexPrivKey.length() % 2 == 1) {
          hexPrivKey = "0" + hexPrivKey;
        }
        try {
          ECPrivateKey privKey = EllipticCurves.getEcPrivateKey(curveType, Hex.decode(hexPrivKey));
          ECPublicKey pubKey = EllipticCurves.getEcPublicKey(Hex.decode(hexPubKey));

          String sharedSecret = Hex.encode(EllipticCurves.computeSharedSecret(privKey, pubKey));
          if (result.equals("invalid")) {
            if (expectedSharedSecret.equals(sharedSecret)
                && WycheproofTestUtil.checkFlags(
                    testcase, "WrongOrder", "WeakPublicKey", "UnnamedCurve")) {
              warnings.add(
                  "WARNING " + tcId + " accepted invalid parameters but shared secret is correct.");
            } else {
              errors.add(
                  "FAIL " + tcId + " accepted invalid parameters, shared secret: " + sharedSecret);
            }
          } else if (!expectedSharedSecret.equals(sharedSecret)) {
            errors.add(
                "FAIL "
                    + tcId
                    + " incorrect shared secret, computed: "
                    + sharedSecret
                    + " expected: "
                    + expectedSharedSecret);
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + " is valid but threw exception: " + ex);
          }
        } catch (Exception ex) {
          errors.add("FAIL " + tcId + " threw unexpected exception: " + ex);
        }
      }
    }
    assertThat(errors).isEmpty();

    // New versions of Conscrypt should not produce any warnings.
    if (!Util.isAndroid() || Util.getAndroidApiLevel() > 25) {
      assertThat(warnings).isEmpty();
    }
  }

  @Test
  public void computeSharedSecretWithPublicPoint() throws Exception {
    // test vector from wycheproof's ecdh_secp256r1_ecpoint_test.json, normal case.
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P256,
            Hex.decode("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346"));
    ECPoint ecPublicPoint =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Hex.decode(
                "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93"
                    + "a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf"));
    byte[] expected =
        Hex.decode("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");

    byte[] sharedSecret = EllipticCurves.computeSharedSecret(ecPrivateKey, ecPublicPoint);
    assertThat(sharedSecret).isEqualTo(expected);

    ECPoint publicPointNotOnCurve =
        new ECPoint(ecPublicPoint.getAffineX(), ecPublicPoint.getAffineY().add(BigInteger.ONE));
    assertThrows(
        GeneralSecurityException.class,
        () -> EllipticCurves.computeSharedSecret(ecPrivateKey, publicPointNotOnCurve));
  }

  @Test
  public void computeSharedSecretWithPublicPointP256() throws Exception {
    // test vector from golang's crypto/ecdh/ecdh_test.go.
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P256,
            Hex.decode("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"));
    ECPoint ecPublicPoint =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Hex.decode(
                "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
                    + "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"));
    byte[] expected =
        Hex.decode("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");

    byte[] sharedSecret = EllipticCurves.computeSharedSecret(ecPrivateKey, ecPublicPoint);
    assertThat(sharedSecret).isEqualTo(expected);
  }

  @Test
  public void computeSharedSecretWithPublicPointP384() throws Exception {
    // test vector from golang's crypto/ecdh/ecdh_test.go.
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P384,
            Hex.decode(
                "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1"));
    ECPoint ecPublicPoint =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P384,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Hex.decode(
                "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066"
                    + "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a"));
    byte[] expected =
        Hex.decode(
            "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1");

    byte[] sharedSecret = EllipticCurves.computeSharedSecret(ecPrivateKey, ecPublicPoint);
    assertThat(sharedSecret).isEqualTo(expected);
  }

  @Test
  public void computeSharedSecretWithPublicPointP521() throws Exception {
    // test vector from golang's crypto/ecdh/ecdh_test.go.
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P521,
            Hex.decode(
                "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47"));
    ECPoint ecPublicPoint =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P521,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Hex.decode(
                "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d"
                    + "01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676"));
    byte[] expected =
        Hex.decode(
            "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831");

    byte[] sharedSecret = EllipticCurves.computeSharedSecret(ecPrivateKey, ecPublicPoint);
    assertThat(sharedSecret).isEqualTo(expected);
  }

  @Test
  public void validateSharedSecret() throws Exception {
    // test vector from wycheproof's ecdh_secp256r1_ecpoint_test.json, normal case.
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(
            EllipticCurves.CurveType.NIST_P256,
            Hex.decode("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346"));
    byte[] sharedSecret =
        Hex.decode("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");
    EllipticCurves.validateSharedSecret(sharedSecret, ecPrivateKey);

    // Most byte strings shorter than sharedSecret are valid.
    byte[] emptySharedSecret = new byte[0];
    EllipticCurves.validateSharedSecret(emptySharedSecret, ecPrivateKey);
    byte[] anotherSharedSecret = Hex.decode("00112233445566778899aabbccddeeff");
    EllipticCurves.validateSharedSecret(anotherSharedSecret, ecPrivateKey);
    byte[] ffSharedSecret = Hex.decode("ffffffffffffffffffffffffffffffffffffffff");
    EllipticCurves.validateSharedSecret(ffSharedSecret, ecPrivateKey);

    // The modulusMinus1 is not a valid secret, because computeY fails.
    byte[] modulusMinus1 =
        Hex.decode("00ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");
    assertThrows(
        GeneralSecurityException.class,
        () -> EllipticCurves.validateSharedSecret(modulusMinus1, ecPrivateKey));

    // The modulus is not a valid secret, because it is out of range.
    byte[] modulus =
        Hex.decode("00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    assertThrows(
        GeneralSecurityException.class,
        () -> EllipticCurves.validateSharedSecret(modulus, ecPrivateKey));
  }
}
