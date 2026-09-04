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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link EcdsaAsn1Util}. */
@RunWith(JUnit4.class)
@AccessesPartialKey
public final class EcdsaAsn1UtilTest {

  // Test case from RFC 6979 A.2.5 (NIST P-256)
  private static final ECPoint HARDCODED_P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger HARDCODED_P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);

  private static final String HARDCODED_P256_SEC1_WITH_BOTH_HEX =
      "3077" // SEQUENCE (119 bytes)
          + "020101" // version: INTEGER 1
          + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" // OCTET STRING
          // 32 bytes
          + "a00a06082a8648ce3d030107" // [0] parameters: P-256 OID 1.2.840.10045.3.1.7
          + "a14403420004" // [1] publicKey: BIT STRING uncompressed point (04 || x || y)
          + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
          + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

  private static final String HARDCODED_P256_SEC1_WITH_PARAMS_HEX =
      "3031" // SEQUENCE (49 bytes)
          + "020101" // version: INTEGER 1
          + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
          + "a00a06082a8648ce3d030107";

  private static final String HARDCODED_P256_SEC1_NO_OPTIONAL_HEX =
      "3025" // SEQUENCE (37 bytes)
          + "020101" // version: INTEGER 1
          + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

  private static final String HARDCODED_P256_SEC1_WITH_PUBLIC_KEY_HEX =
      "306b" // SEQUENCE (107 bytes)
          + "020101" // version: INTEGER 1
          + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
          + "a14403420004" // [1] publicKey
          + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
          + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

  // Test case from RFC 6979 A.2.6 (NIST P-384)
  private static final ECPoint HARDCODED_P384_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "9D92E0330DFC60BA8B2BE32E10F7D2F8457678A112CAFD4544B29B7E6ADDF0249968F54C"
                  + "732AA49BC4A38F467EDB8424",
              16),
          new BigInteger(
              "81A3A9C9E878B86755F018A8EC3C5E80921910AF919B95F18976E35ACC04EFA2962E277A"
                  + "0B2C990AE92B62D6C75180BA",
              16));
  private static final BigInteger HARDCODED_P384_PRIVATE_VALUE =
      new BigInteger(
          "670DC60402D8A4FE52F4E552D2B71F0F81BCF195D8A71A6C7D84EFB4F0E4B4A5D0F60A27C9"
              + "4CAAC46BDEEB79897A3ED9",
          16);

  private static final String HARDCODED_P384_SEC1_WITH_PARAMS_HEX =
      "303e" // SEQUENCE (62 bytes)
          + "020101" // version: INTEGER 1
          + "0430670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9"
          + "a00706052b81040022";

  // Test case from RFC 6979 A.2.7 (NIST P-521)
  private static final ECPoint HARDCODED_P521_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                  + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                  + "3A4",
              16),
          new BigInteger(
              "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                  + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                  + "CF5",
              16));
  private static final BigInteger HARDCODED_P521_PRIVATE_VALUE =
      new BigInteger(
          "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
              + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
              + "538",
          16);

  private static final String HARDCODED_P521_SEC1_WITH_PARAMS_HEX =
      "3050" // SEQUENCE (80 bytes)
          + "020101" // version: INTEGER 1
          + "044200fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538"
          + "a00706052b81040023";

  private static EcdsaPublicKey createHardcodedP256PublicKey() throws Exception {
    EcdsaParameters params =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    return EcdsaPublicKey.builder()
        .setParameters(params)
        .setPublicPoint(HARDCODED_P256_PUBLIC_POINT)
        .build();
  }

  private static EcdsaPublicKey createHardcodedP384PublicKey() throws Exception {
    EcdsaParameters params =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    return EcdsaPublicKey.builder()
        .setParameters(params)
        .setPublicPoint(HARDCODED_P384_PUBLIC_POINT)
        .build();
  }

  private static EcdsaPublicKey createHardcodedP521PublicKey() throws Exception {
    EcdsaParameters params =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    return EcdsaPublicKey.builder()
        .setParameters(params)
        .setPublicPoint(HARDCODED_P521_PUBLIC_POINT)
        .build();
  }

  @Test
  public void ecdsaSec1_p256_roundtrip_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1Bytes, pubKey.getParameters(), InsecureSecretKeyAccess.get());

    assertThat(parsedKey.getParameters()).isEqualTo(pubKey.getParameters());
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(privKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
  }

  @Test
  public void ecdsaSec1_p384_roundtrip_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP384PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1Bytes, pubKey.getParameters(), InsecureSecretKeyAccess.get());

    assertThat(parsedKey.getParameters()).isEqualTo(pubKey.getParameters());
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(privKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
  }

  @Test
  public void ecdsaSec1_p521_roundtrip_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP521PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1Bytes, pubKey.getParameters(), InsecureSecretKeyAccess.get());

    assertThat(parsedKey.getParameters()).isEqualTo(pubKey.getParameters());
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(privKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_p256_matchesExpected() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    assertThat(Hex.encode(sec1Bytes)).isEqualTo(HARDCODED_P256_SEC1_WITH_PARAMS_HEX);
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_p384_matchesExpected() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP384PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    assertThat(Hex.encode(sec1Bytes)).isEqualTo(HARDCODED_P384_SEC1_WITH_PARAMS_HEX);
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_p521_matchesExpected() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP521PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    byte[] sec1Bytes =
        EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get());
    assertThat(Hex.encode(sec1Bytes)).isEqualTo(HARDCODED_P521_SEC1_WITH_PARAMS_HEX);
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_nullAccess_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, null));
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_invalidVariant_throws() throws Exception {
    for (EcdsaParameters.Variant variant :
        new EcdsaParameters.Variant[] {
          EcdsaParameters.Variant.TINK,
          EcdsaParameters.Variant.CRUNCHY,
          EcdsaParameters.Variant.LEGACY
        }) {
      EcdsaParameters params =
          EcdsaParameters.builder()
              .setHashType(EcdsaParameters.HashType.SHA256)
              .setCurveType(EcdsaParameters.CurveType.NIST_P256)
              .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
              .setVariant(variant)
              .build();
      EcdsaPublicKey pubKey =
          EcdsaPublicKey.builder()
              .setParameters(params)
              .setPublicPoint(HARDCODED_P256_PUBLIC_POINT)
              .setIdRequirement(variant == EcdsaParameters.Variant.NO_PREFIX ? null : 123)
              .build();
      EcdsaPrivateKey privKey =
          EcdsaPrivateKey.builder()
              .setPublicKey(pubKey)
              .setPrivateValue(
                  SecretBigInteger.fromBigInteger(
                      HARDCODED_P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
              .build();

      assertThrows(
          GeneralSecurityException.class,
          () -> EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get()));
    }
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_invalidSignatureEncoding_throws() throws Exception {
    EcdsaParameters params =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey pubKey =
        EcdsaPublicKey.builder()
            .setParameters(params)
            .setPublicPoint(HARDCODED_P256_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void ecdsaPrivateKeyToSec1Bytes_p384WithSha512_throws() throws Exception {
    EcdsaParameters params =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey pubKey =
        EcdsaPublicKey.builder()
            .setParameters(params)
            .setPublicPoint(HARDCODED_P384_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey privKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(pubKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    HARDCODED_P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> EcdsaAsn1Util.ecdsaPrivateKeyToSec1Bytes(privKey, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_nullAccess_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1NoOptional = Hex.decode(HARDCODED_P256_SEC1_NO_OPTIONAL_HEX);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
                sec1NoOptional, pubKey.getParameters(), null));
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_noOptionalFields_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1NoOptional = Hex.decode(HARDCODED_P256_SEC1_NO_OPTIONAL_HEX);

    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1NoOptional, pubKey.getParameters(), InsecureSecretKeyAccess.get());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(HARDCODED_P256_PRIVATE_VALUE);
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_withBothParamsAndPublicKey_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1WithBoth = Hex.decode(HARDCODED_P256_SEC1_WITH_BOTH_HEX);

    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1WithBoth, pubKey.getParameters(), InsecureSecretKeyAccess.get());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(HARDCODED_P256_PRIVATE_VALUE);
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_withOnlyPublicKey_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1OnlyPubKey = Hex.decode(HARDCODED_P256_SEC1_WITH_PUBLIC_KEY_HEX);

    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1OnlyPubKey, pubKey.getParameters(), InsecureSecretKeyAccess.get());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(HARDCODED_P256_PRIVATE_VALUE);
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_withCompressedPublicKey_works() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1CompressedPubKey =
        Hex.decode(
            "304b" // SEQUENCE (75 bytes)
                + "020101" // version: INTEGER 1
                + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
                + "a12403220003" // [1] compressed publicKey (0x03 prefix)
                + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");

    EcdsaPrivateKey parsedKey =
        EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
            sec1CompressedPubKey, pubKey.getParameters(), InsecureSecretKeyAccess.get());
    assertThat(parsedKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(HARDCODED_P256_PRIVATE_VALUE);
    assertThat(parsedKey.getPublicKey().getPublicPoint()).isEqualTo(pubKey.getPublicPoint());
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_curveOidMismatch_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] invalidOidSec1 =
        Hex.decode(
            "302e"
                + "020101"
                + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
                + "a00706052b81040022");

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
                invalidOidSec1, pubKey.getParameters(), InsecureSecretKeyAccess.get()));
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_invalidVersion_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] invalidVersionSec1 =
        Hex.decode(HARDCODED_P256_SEC1_WITH_PARAMS_HEX.replace("020101", "020102"));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
                invalidVersionSec1, pubKey.getParameters(), InsecureSecretKeyAccess.get()));
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_invalidTrailingTag_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1InvalidTag =
        Hex.decode(
            "302a" // SEQUENCE of 42 bytes
                + "020101" // INTEGER 1
                + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
                + "a203020101"); // [2] invalid tag

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
                sec1InvalidTag, pubKey.getParameters(), InsecureSecretKeyAccess.get()));
  }

  @Test
  public void sec1EcKeyToEcdsaPrivateKey_invalidPublicKey_throws() throws Exception {
    EcdsaPublicKey pubKey = createHardcodedP256PublicKey();
    byte[] sec1InvalidPubKey =
        Hex.decode(
            "302c"
                + "020101"
                + "0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
                + "a1050303000501"); // [1] BIT STRING with invalid format byte (0x05)

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
                sec1InvalidPubKey, pubKey.getParameters(), InsecureSecretKeyAccess.get()));
  }
}
