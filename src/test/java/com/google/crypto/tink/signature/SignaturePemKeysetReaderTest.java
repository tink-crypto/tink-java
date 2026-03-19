// Copyright 2017 Google LLC
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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.LegacyKeysetSerialization;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.ECPoint;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for SignaturePemKeysetReader */
@RunWith(Theories.class)
public final class SignaturePemKeysetReaderTest {

  private static boolean conscryptIsAvailable() {
    try {
      return Conscrypt.isAvailable();
    } catch (Throwable e) {
      return false;
    }
  }

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    MlDsaProtoSerialization.register();
    if (!Util.isAndroid() && conscryptIsAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void read_oneRSAPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

    // Extracted after converting the PEM to JWK.
    BigInteger expectedModulus = new BigInteger(1, Base64.urlSafeDecode(
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ"));
    RsaSsaPssParameters expectedParams = RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pem, PemKeyType.RSA_PSS_2048_SHA256)
            .buildPublicKeysetHandle();

    assertThat(handle.size()).isEqualTo(1);
    RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) handle.getAt(0).getKey();

    assertThat(key.getParameters()).isEqualTo(expectedParams);
    assertThat(key.getModulus()).isEqualTo(expectedModulus);
  }

  @Test
  public void sha256WithRSAEncryption_isAlwaysAccepted() throws Exception {
    // This PEM uses OID sha256WithRSAEncryption (1 2 840 113549 1 1 11), see RFC 4055.
    // This OID should normally only be used with RSA SSA PKCS1 signatures with SHA256.

    // from: wycheproof/testvectors/rsa_signature_test.json
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAoHiH83M3gZawt0jN8xwU\n"
            + "c1zPoPEXrK/aoh/eS251WTkLg057kunhzJ1J/A/mz7YEKWUrS/mndo9x/EJxym/v\n"
            + "TkMRkuvcmGML+5TFuvGLTPeIHYRIPkxEwi2xWpYncFoLQqJtbz1gCa7g0qcb7fTU\n"
            + "sO5rb+wvFuEnfsqjve26QGRzpHbRaI3w+tHaeVUmx+ZBmBtIErBbaS1gxgsr+kJM\n"
            + "i2IPQNydulnixxDn7nULPhNMH3H0MhBoiv8XqqQc21ZodT8ABrHPlRvFlR9NiaMR\n"
            + "lphepVwJZsNmK8/k5M008S5K/X5cShMHObEBfWpYOIL9ctsaZ0GHAsiwE1PM91t7\n"
            + "k/rsDgvjYhHV8r2RDhVSMjcRu+tzhY+JnMHsBj72fYjgxpnVponFIQbwbpYPCdKj\n"
            + "z4T1O76ipHPt8ubgF2gB0/ocLTWOHlom9kask3luwfrcaZHA7BnJ3ZCyWi3Tv3PS\n"
            + "zx7qiGf5bKpaLfVJc6yyotoKE2fsdK+7lo9Rd2UjjRdpAgMBAAE=\n"
            + "-----END PUBLIC KEY-----\n";

    String expectedModulusHex =
        "a07887f373378196b0b748cdf31c14735ccfa0f117acafdaa21fde4b6e7559390b834e7b92e9e1cc9d49f"
            + "c0fe6cfb60429652b4bf9a7768f71fc4271ca6fef4e431192ebdc98630bfb94c5baf18b4cf7881d"
            + "84483e4c44c22db15a9627705a0b42a26d6f3d6009aee0d2a71bedf4d4b0ee6b6fec2f16e1277ec"
            + "aa3bdedba406473a476d1688df0fad1da795526c7e641981b4812b05b692d60c60b2bfa424c8b62"
            + "0f40dc9dba59e2c710e7ee750b3e134c1f71f43210688aff17aaa41cdb5668753f0006b1cf951bc"
            + "5951f4d89a31196985ea55c0966c3662bcfe4e4cd34f12e4afd7e5c4a130739b1017d6a583882fd"
            + "72db1a67418702c8b01353ccf75b7b93faec0e0be36211d5f2bd910e1552323711bbeb73858f899"
            + "cc1ec063ef67d88e0c699d5a689c52106f06e960f09d2a3cf84f53bbea2a473edf2e6e0176801d3"
            + "fa1c2d358e1e5a26f646ac93796ec1fadc6991c0ec19c9dd90b25a2dd3bf73d2cf1eea8867f96ca"
            + "a5a2df54973acb2a2da0a1367ec74afbb968f517765238d1769";
    BigInteger expectedModulus = new BigInteger(1, Hex.decode(expectedModulusHex));

    {
      // import as PSS.
      // This works, even though sha256WithRSAEncryption should normally not be used with PSS.
      RsaSsaPssParameters expectedParams =
          RsaSsaPssParameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(RsaSsaPssParameters.F4)
              .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
              .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
              .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
              .setSaltLengthBytes(32)
              .build();

    KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
            .addPem(pem, PemKeyType.RSA_PSS_3072_SHA256)
            .buildPublicKeysetHandle();

      assertThat(handle.size()).isEqualTo(1);
      RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) handle.getAt(0).getKey();

      assertThat(key.getParameters()).isEqualTo(expectedParams);
      assertThat(key.getModulus()).isEqualTo(expectedModulus);
    }

    {
      // import as PKCS1.
      RsaSsaPkcs1Parameters expectedParams =
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(RsaSsaPkcs1Parameters.F4)
              .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .build();

      KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
              .addPem(pem, PemKeyType.RSA_SIGN_PKCS1_3072_SHA256)
              .buildPublicKeysetHandle();

      assertThat(handle.size()).isEqualTo(1);
      RsaSsaPkcs1PublicKey key = (RsaSsaPkcs1PublicKey) handle.getAt(0).getKey();

      assertThat(key.getParameters()).isEqualTo(expectedParams);
      assertThat(key.getModulus()).isEqualTo(expectedModulus);
    }
  }

  @Test
  public void sha384withRsaPublicKey_isAcceptedWhenNotOnAndroid() throws Exception {
    // This PEM uses OID SHA384withRSA (1 2 840 113549 1 1 12), see RFC 4055.
    // This OID should normally only be used with RSA SSA PKCS1 signatures with SHA384.

    // from: wycheproof/testvectors/rsa_signature_test.json, and manually changed one byte.
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBojANBgkqhkiG9w0BAQwFAAOCAY8AMIIBigKCAYEAoHiH83M3gZawt0jN8xwU\n"
            + "c1zPoPEXrK/aoh/eS251WTkLg057kunhzJ1J/A/mz7YEKWUrS/mndo9x/EJxym/v\n"
            + "TkMRkuvcmGML+5TFuvGLTPeIHYRIPkxEwi2xWpYncFoLQqJtbz1gCa7g0qcb7fTU\n"
            + "sO5rb+wvFuEnfsqjve26QGRzpHbRaI3w+tHaeVUmx+ZBmBtIErBbaS1gxgsr+kJM\n"
            + "i2IPQNydulnixxDn7nULPhNMH3H0MhBoiv8XqqQc21ZodT8ABrHPlRvFlR9NiaMR\n"
            + "lphepVwJZsNmK8/k5M008S5K/X5cShMHObEBfWpYOIL9ctsaZ0GHAsiwE1PM91t7\n"
            + "k/rsDgvjYhHV8r2RDhVSMjcRu+tzhY+JnMHsBj72fYjgxpnVponFIQbwbpYPCdKj\n"
            + "z4T1O76ipHPt8ubgF2gB0/ocLTWOHlom9kask3luwfrcaZHA7BnJ3ZCyWi3Tv3PS\n"
            + "zx7qiGf5bKpaLfVJc6yyotoKE2fsdK+7lo9Rd2UjjRdpAgMBAAE=\n"
            + "-----END PUBLIC KEY-----\n";

    if (Util.isAndroid()) {
      // Is not supported on Android.
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            SignaturePemKeysetReader.newBuilder()
                .addPem(pem, PemKeyType.RSA_PSS_3072_SHA256)
                .buildPublicKeysetHandle();
          });
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            SignaturePemKeysetReader.newBuilder()
                .addPem(pem, PemKeyType.RSA_SIGN_PKCS1_3072_SHA256)
                .buildPublicKeysetHandle();
          });
      return;
    }

    String expectedModulusHex =
        "a07887f373378196b0b748cdf31c14735ccfa0f117acafdaa21fde4b6e7559390b834e7b92e9e1cc9d49f"
            + "c0fe6cfb60429652b4bf9a7768f71fc4271ca6fef4e431192ebdc98630bfb94c5baf18b4cf7881d"
            + "84483e4c44c22db15a9627705a0b42a26d6f3d6009aee0d2a71bedf4d4b0ee6b6fec2f16e1277ec"
            + "aa3bdedba406473a476d1688df0fad1da795526c7e641981b4812b05b692d60c60b2bfa424c8b62"
            + "0f40dc9dba59e2c710e7ee750b3e134c1f71f43210688aff17aaa41cdb5668753f0006b1cf951bc"
            + "5951f4d89a31196985ea55c0966c3662bcfe4e4cd34f12e4afd7e5c4a130739b1017d6a583882fd"
            + "72db1a67418702c8b01353ccf75b7b93faec0e0be36211d5f2bd910e1552323711bbeb73858f899"
            + "cc1ec063ef67d88e0c699d5a689c52106f06e960f09d2a3cf84f53bbea2a473edf2e6e0176801d3"
            + "fa1c2d358e1e5a26f646ac93796ec1fadc6991c0ec19c9dd90b25a2dd3bf73d2cf1eea8867f96ca"
            + "a5a2df54973acb2a2da0a1367ec74afbb968f517765238d1769";
    BigInteger expectedModulus = new BigInteger(1, Hex.decode(expectedModulusHex));


    // When not on Android, this is accepted.

    {
      // import as PSS.
      // This works, even though sha384WithRSAEncryption should normally not be used with PSS.
      // Also, the hash function is wrong, which is ignored.
      RsaSsaPssParameters expectedParams =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();

      KeysetHandle handle =
          SignaturePemKeysetReader.newBuilder()
              .addPem(pem, PemKeyType.RSA_PSS_3072_SHA256)
              .buildPublicKeysetHandle();

      assertThat(handle.size()).isEqualTo(1);
      RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) handle.getAt(0).getKey();

      assertThat(key.getParameters()).isEqualTo(expectedParams);
      assertThat(key.getModulus()).isEqualTo(expectedModulus);
    }
    {
      // import as PKCS1 with SHA256.
      // The hash function is wrong, which is ignored.
      RsaSsaPkcs1Parameters expectedParams =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();

      KeysetHandle handle =
          SignaturePemKeysetReader.newBuilder()
              .addPem(pem, PemKeyType.RSA_SIGN_PKCS1_3072_SHA256)
              .buildPublicKeysetHandle();

      assertThat(handle.size()).isEqualTo(1);
      RsaSsaPkcs1PublicKey key = (RsaSsaPkcs1PublicKey) handle.getAt(0).getKey();

      assertThat(key.getParameters()).isEqualTo(expectedParams);
      assertThat(key.getModulus()).isEqualTo(expectedModulus);
    }
  }



  @Test
  public void read_oneECPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    // Extracted after converting the PEM to JWK.
    String expectedXBase64 = "7BiT5K5pivl4Qfrt9hRhRREMUzj_8suEJ7GlMxZfvdc";
    String expectedYBase64 = "KW4vxoWD7iYvBp9h9TWjCWXC2aOTCzysshk-bt7tVQU";
    ECPoint expectedPoint =
        new ECPoint(
            new BigInteger(1, Base64.urlSafeDecode(expectedXBase64)),
            new BigInteger(1, Base64.urlSafeDecode(expectedYBase64)));
    EcdsaParameters expectedParams = EcdsaParameters.builder()
        .setHashType(EcdsaParameters.HashType.SHA256)
        .setCurveType(EcdsaParameters.CurveType.NIST_P256)
        .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
        .setVariant(EcdsaParameters.Variant.NO_PREFIX)
        .build();

    KeysetHandle handle =
            SignaturePemKeysetReader.newBuilder()
                .addPem(pem, PemKeyType.ECDSA_P256_SHA256)
                .buildPublicKeysetHandle();

    EcdsaPublicKey publicKey = (EcdsaPublicKey) handle.getAt(0).getKey();
    assertThat(publicKey.getParameters()).isEqualTo(expectedParams);
    assertThat(publicKey.getPublicPoint()).isEqualTo(expectedPoint);
  }

  @Test
  public void rsaSizeMismatch_shouldIgnore() throws Exception {
    String rsa2048Pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
            .addPem(rsa2048Pem, PemKeyType.RSA_SIGN_PKCS1_2048_SHA256)
            .addPem(rsa2048Pem, PemKeyType.RSA_SIGN_PKCS1_3072_SHA256)  // is ignored.
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }


@Test
  public void ecWrongCurve_shouldIgnore() throws Exception {
    String p256Pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(p256Pem, PemKeyType.ECDSA_P256_SHA256)
            .addPem(p256Pem, PemKeyType.ECDSA_P384_SHA384) // wrong curve, is ignored.
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }

  @Test
  public void whenNoKeysAreValid_throwsAndIncludesFirstException() throws Exception {
    String p256Pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    Exception exception =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                SignaturePemKeysetReader.newBuilder()
                    .addPem(p256Pem, PemKeyType.ECDSA_P384_SHA384) // wrong curve
                    .buildPublicKeysetHandle());
    assertThat(exception)
        .hasMessageThat()
        .contains("wrong NIST curve: found curve with 256 bits, expected 384 bits");
  }

  @Test
  public void read_onePEM_twoRSAPublicKeys_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n"
            + "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHT+woDZHckRv316VyUw\n"
            + "WnQ8lR7C1rOj+KPuBnAPMQTW8htNG0gfjYEb01ZRvZM8ezOunDnpBqvYPeATKTGu\n"
            + "YD7/Tq1gkcFGf59aG2vgi8I/+0OkYNyWwuYLKm34t50TKMvQwiIBr0IZfaGnzF/5\n"
            + "43wqtE6rvcZTavlR0q3ftJQ6OEFXnOzShRctQf7nIn2Mi2mks3cLoWpqLJe0rSiM\n"
            + "TYqas+fiLd5K5p55H2woBpoRPBmNEBMd2r+P0caGNRd3XuO2OwOx/2XezZ0Lj9ms\n"
            + "u7BDXM/No6dxLmrgwzokuRg0N/mF+PUCnNakbT1nyn/1uMopialAMDhYUEtZdFjw\n"
            + "gwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

    // Extracted after converting the PEM to JWK.
    BigInteger expectedModulus = new BigInteger(1, Base64.urlSafeDecode(
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ"));

    KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
                .addPem(pem, PemKeyType.RSA_PSS_2048_SHA256)
                .buildPublicKeysetHandle();

    // Test that both handles have the same keys. Because the key ids are chosen at random,
    // they are not exactly the same keysets.
    assertThat(handle.size()).isEqualTo(2);
    assertThat(handle.getAt(0).isPrimary()).isTrue();

    RsaSsaPssPublicKey firstKey = (RsaSsaPssPublicKey) handle.getAt(0).getKey();
    RsaSsaPssPublicKey secondKey = (RsaSsaPssPublicKey) handle.getAt(1).getKey();

    RsaSsaPssParameters expectedParams = RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(firstKey.getParameters()).isEqualTo(expectedParams);
    assertThat(firstKey.getModulus()).isEqualTo(expectedModulus);
    assertThat(secondKey.getParameters()).isEqualTo(expectedParams);
  }

  @Test
  public void read_onePEM_oneRSAPublicKey_oneECPublicKey_eCPublicKeyShouldBeIgnored()
      throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n"
            + "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    // Extracted after converting the PEM to JWK.
    BigInteger expectedModulus = new BigInteger(1, Base64.urlSafeDecode(
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ"));

    KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
                .addPem(pem, PemKeyType.RSA_PSS_2048_SHA256)
                .buildPublicKeysetHandle();

    // The EC public key is ignored because it has the wrong type. It is not a RSA_PSS_2048_SHA256
    // key.
    assertThat(handle.size()).isEqualTo(1);
    RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build());
    assertThat(key.getModulus()).isEqualTo(expectedModulus);
  }

  @Test
  public void read_twoPEMs_oneRSAPublicKey_oneECPublicKey_shouldWork() throws Exception {
    String rsaPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    String ecPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle = SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .buildPublicKeysetHandle();

    // Extracted after converting the PEM to JWK.
    BigInteger expectedModulus = new BigInteger(1, Base64.urlSafeDecode(
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ"));
    RsaSsaPssParameters expectedRsaSsaPssParams = RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();

    String expectedXBase64 = "7BiT5K5pivl4Qfrt9hRhRREMUzj_8suEJ7GlMxZfvdc";
    String expectedYBase64 = "KW4vxoWD7iYvBp9h9TWjCWXC2aOTCzysshk-bt7tVQU";
    ECPoint expectedPoint =
        new ECPoint(
            new BigInteger(1, Base64.urlSafeDecode(expectedXBase64)),
            new BigInteger(1, Base64.urlSafeDecode(expectedYBase64)));
    EcdsaParameters expectedEcdsaParams = EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    assertThat(handle.size()).isEqualTo(2);

    assertThat(handle.getAt(0).isPrimary()).isTrue();
    RsaSsaPssPublicKey firstKey = (RsaSsaPssPublicKey) handle.getAt(0).getKey();
    assertThat(firstKey.getParameters()).isEqualTo(expectedRsaSsaPssParams);
    assertThat(firstKey.getModulus()).isEqualTo(expectedModulus);

    EcdsaPublicKey secondKey = (EcdsaPublicKey) handle.getAt(1).getKey();
    assertThat(secondKey.getParameters()).isEqualTo(expectedEcdsaParams);
    assertThat(secondKey.getPublicPoint()).isEqualTo(expectedPoint);
  }

  @Test
  public void deprecatedBuildWithLegacyKeysetReader_isEquivalentToBuildPublicKeysetHandle() throws Exception {
    String rsaPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    String ecPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    // Extracted after converting the PEM to JWK.
    BigInteger expectedModulus = new BigInteger(1, Base64.urlSafeDecode(
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ"));
    RsaSsaPssParameters expectedRsaSsaPssParams = RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPkcs1Parameters expectedRsaPkcs1Params = RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    String expectedXBase64 = "7BiT5K5pivl4Qfrt9hRhRREMUzj_8suEJ7GlMxZfvdc";
    String expectedYBase64 = "KW4vxoWD7iYvBp9h9TWjCWXC2aOTCzysshk-bt7tVQU";
    ECPoint expectedPoint =
        new ECPoint(
            new BigInteger(1, Base64.urlSafeDecode(expectedXBase64)),
            new BigInteger(1, Base64.urlSafeDecode(expectedYBase64)));

    EcdsaParameters expectedEcdsaParams = EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPem, PemKeyType.RSA_SIGN_PKCS1_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .buildPublicKeysetHandle();

    assertThat(handle.size()).isEqualTo(3);
    RsaSsaPssPublicKey rsaPssKey = (RsaSsaPssPublicKey) handle.getAt(0).getKey();
    assertThat(rsaPssKey.getParameters()).isEqualTo(expectedRsaSsaPssParams);
    assertThat(rsaPssKey.getModulus()).isEqualTo(expectedModulus);

    RsaSsaPkcs1PublicKey rsaPkcs1Key =
        (RsaSsaPkcs1PublicKey) handle.getAt(1).getKey();
    assertThat(rsaPkcs1Key.getParameters()).isEqualTo(expectedRsaPkcs1Params);
    assertThat(rsaPkcs1Key.getModulus()).isEqualTo(expectedModulus);

    EcdsaPublicKey ecdsaKey = (EcdsaPublicKey) handle.getAt(2).getKey();
    assertThat(ecdsaKey.getParameters()).isEqualTo(expectedEcdsaParams);
    assertThat(ecdsaKey.getPublicPoint()).isEqualTo(expectedPoint);

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPem, PemKeyType.RSA_SIGN_PKCS1_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .build();
    KeysetHandle legacyHandle = LegacyKeysetSerialization.parseKeysetWithoutSecret(keysetReader);

    // verify that legacyHandle has the same keys, except for the key IDs.
    assertThat(legacyHandle.size()).isEqualTo(3);
    assertThat(legacyHandle.getAt(0).isPrimary()).isTrue();
    assertThat(legacyHandle.getAt(0).getKey().equalsKey(rsaPssKey)).isTrue();
    assertThat(legacyHandle.getAt(1).getKey().equalsKey(rsaPkcs1Key)).isTrue();
    assertThat(legacyHandle.getAt(2).getKey().equalsKey(ecdsaKey)).isTrue();


  }

  @Test
  public void deprecatedBuild_emptyReader_readThrowsIOException() throws Exception {
    KeysetReader keysetReader = SignaturePemKeysetReader.newBuilder().build();
    assertThrows(IOException.class, keysetReader::read);
  }

  @Test
  public void deprecatedBuild_readTwice_works() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256).build();
    Keyset ks1 = keysetReader.read();
    Keyset ks2 = keysetReader.read();

    assertThat(ks1.getKeyCount()).isEqualTo(1);
    assertThat(ks2.getKeyCount()).isEqualTo(1);
  }

  @Test
  public void deprecatedBuild_callBuildTwice_works() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    SignaturePemKeysetReader.Builder builder =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256);

    KeysetReader keysetReader1 = builder.build();
    KeysetReader keysetReader2 = builder.build();

    Keyset ks1 = keysetReader1.read();
    Keyset ks2 = keysetReader2.read();

    assertThat(ks1.getKeyCount()).isEqualTo(1);
    assertThat(ks2.getKeyCount()).isEqualTo(1);
  }

  @Test
  public void deprecatedBuild_callAddAfterBuild_doesNotAffectExistingReader() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    SignaturePemKeysetReader.Builder builder =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256);
    KeysetReader keysetReader1 = builder.build();

    builder.addPem(pem, PemKeyType.ECDSA_P256_SHA256);

    Keyset ks1 = keysetReader1.read();

    KeysetReader keysetReader2 = builder.build();
    Keyset ks2 = keysetReader2.read();

    assertThat(ks1.getKeyCount()).isEqualTo(1);
    assertThat(ks2.getKeyCount()).isEqualTo(2);
  }

  @Test
  public void buildPublicKeysetHandle_invalidKeys_areIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem("invalid", PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem("invalid2", PemKeyType.ECDSA_P256_SHA256)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }

  @Test
  public void buildPublicKeysetHandle_withRsaPrivateKey_isIgnored() throws Exception {
    String rsaPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    String rsaPrivateKeyPem =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEAsll1i7Arx1tosXYSyb9oxfoFlYozTGHhZ7wgvMdXV8Em6JIQ\n"
            + "ud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli3oxxvS217GJdollxL4ao3D0kHpaI\n"
            + "yCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alXimIsgsD89vae82cOOL/JD2PaTzu7\n"
            + "0IjIrno8WlXmb2R01WLTLM57ft188BScoOlstlJegfu6gVqPEnSONOUTX1crLhe3\n"
            + "ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7NzBy31Y0TiWk9Qzd/Tz3pScseQQXn\n"
            + "krltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8ihQIDAQABAoIBAHYrXf3bEXa6syh6\n"
            + "AkLYZzRdz5tggVLHu9C+zrYmIlILsZsBRMHTDM0lCv5hAsTvI9B7LLJBJT8rKt2y\n"
            + "SiaAGKk6RxZAljx0hHPQbXU+9N1QSYFW3nQ1VRR5NoUfs6OPfapSM8pz3OoSjQnX\n"
            + "VG94c39GQxWzhyifCXxeuQaS1EY0F8g9HKkSdRbvsNVF/2j+rdmWeur8swtYBDCN\n"
            + "nBymiDhEBj/Y1Ft3R6ywC14YM/af4aDWTbhQvZYPtITdoEtOWulGkqcx0j/NlMYU\n"
            + "SZcaG3M/6UuKXGzibtO4w9LlI00HPlBDi3fQGbezk6WyLNjcE4xj/MKFg7VosgN7\n"
            + "XDy68tUCgYEA6FovqDcya6JxivhyVZks98e22sPARwpowI3Nt+gsF5uPcqQMvbot\n"
            + "ACzKHjqxRJyGbioMUI8Ao20/f2PxzeI5wAtH2HPNaN6bCbBXvxlCTMCAokbHSWjW\n"
            + "stK2PXl2cqF/51ED7EPbgxABetGyfudsx22QowSR66Sq3I8UtZnQVUMCgYEAxIBC\n"
            + "EW2oLh9ZUKxEeMuFlMN1FJCCqIx3zeVjUtAC3Vm/VvodEL0KM7w9Y123BfeoWMnG\n"
            + "HaqNUEZRUO/bMvaiIXVykF19NTCxym4s6eKNBwGsdWvxroRm0k37uhflt9A7iVX6\n"
            + "HmDVPYgjLJbPmLc8+Ms5ML6Od7qXKajRFOPmSJcCgYEA28JY6s/x9013+InNkdpD\n"
            + "ZsNU1gpo9IgK1XwJQ1TrRxTRkwtIJbZN06mJLRg0C4HDv7QzW4o1f1zXvsQnsqOy\n"
            + "HUpOFJJKiFJq7roD8/GO/Irh3xn0aSEoV4/l37Te68KF96FvhWoU1xwvWhu1qEN4\n"
            + "ZhLhxt2OqgJfvCXz32LwYYMCgYBVEL0JNHJw/Qs6PEksDdcXLoI509FsS9r1XE9i\n"
            + "I0CKOHb3nTEF9QA8o0nkAUbhI3RSc477esDQNpCvPBalelV3rJNa4c35P8pHuuhg\n"
            + "m723gcb50i/+/7xPYIkP55Z/u3p6mqi7i+nkSFIJ1IOsNe8EOV3ZtzSPqkwUMcvJ\n"
            + "gltHowKBgQDkB76QzH3xb4jABKehkCxVxqyGLKxU7SOZpLpCc/5OHbo12u/CwlwG\n"
            + "uAeidKZk3SJEmj0F1+Aiir2KRv+RX543VvzCtEXNkVViVrirzvjZUGKPdkMWfbF8\n"
            + "OdD7qHPPNu5jSyaroeN6VqfbELpewhYzulMEipckEZlU4+Dxu2k1eQ==\n"
            + "-----END RSA PRIVATE KEY-----\n";
    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPublicKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPrivateKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey())
        .isInstanceOf(RsaSsaPssPublicKey.class);
  }

  @Test
  public void buildPublicKeysetHandle_withEcPrivateKey_isIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    String ecPrivateKeyPem =
        "-----BEGIN EC PRIVATE KEY-----"
            + "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49\n"
            + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l\n"
            + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==\n"
            + "-----END EC PRIVATE KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPrivateKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey())
        .isInstanceOf(EcdsaPublicKey.class);
  }

  @Test
  public void buildPublicKeysetHandle_withEd25519PublicKey_works() throws Exception {
    // from RFC 8410, Section 10.1
    String ed25519PublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
         + "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
         + "-----END PUBLIC KEY-----\n";
    byte[] expectedKeyBytes = Hex.decode(
        "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ed25519PublicKeyPem, PemKeyType.ED25519)
            .buildPublicKeysetHandle();

    assertThat(handle.size()).isEqualTo(1);
    Ed25519PublicKey publicKey = (Ed25519PublicKey) handle.getAt(0).getKey();
    assertThat(publicKey.getPublicKeyBytes().toByteArray()).isEqualTo(expectedKeyBytes);
  }

  @Test
  public void ed25519_wrongPem_isIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    String ed25519PublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
         + "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
         + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ecPublicKeyPem, PemKeyType.ED25519)  // wrong PEM format. Is ignored.
            .addPem(ed25519PublicKeyPem, PemKeyType.ED25519)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }

  @Test
  public void ed25519_invalidPem_isIgnored() throws Exception {
    String ed25519PublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
         + "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
         + "-----END PUBLIC KEY-----\n";
    String invalidEd25519Pem =
        "-----BEGIN PUBLIC KEY-----\n"
         + "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbL\n"
         + "-----END PUBLIC KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(invalidEd25519Pem, PemKeyType.ED25519) // invalid PEM. Is ignored.
            .addPem(ed25519PublicKeyPem, PemKeyType.ED25519)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }

  // From:
  // https://datatracker.ietf.org/doc/html/rfc9881#name-example-public-keys
  private static final String ML_DSA_65_PUBLIC_KEY_PEM =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIHsjALBglghkgBZQMEAxIDggehAEhoPZGXjjHrPd24sEc0gtK4il9iWUn9j1il\n"
          + "YeaWvUwn0Fs427Lt8B5mTv2Bvh6ok2iM5oqi1RxZWPi7xutOie5n0sAyCVTVchLK\n"
          + "xyKf8dbq8DkovVFRH42I2EdzbH3icw1ZeOVBBxMWCXiGdxG/VTmgv8TDUMK+Vyuv\n"
          + "DuLi+xbM/qCAKNmaxJrrt1k33c4RHNq2L/886ouiIz0eVvvFxaHnJt5j+t0q8Bax\n"
          + "GRd/o9lxotkncXP85VtndFrwt8IdWX2+uT5qMvNBxJpai+noJQiNHyqkUVXWyK4V\n"
          + "Nn5OsAO4/feFEHGUlzn5//CQI+r0UQTSqEpFkG7tRnGkTcKNJ5h7tV32np6FYfYa\n"
          + "gKcmmVA4Zf7Zt+5yqOF6GcQIFE9LKa/vcDHDpthXFhC0LJ9CEkWojxl+FoErAxFZ\n"
          + "tluWh+Wz6TTFIlrpinm6c9Kzmdc1EO/60Z5TuEUPC6j84QEv2Y0mCnSqqhP64kmg\n"
          + "BrHDT1uguILyY3giL7NvIoPCQ/D/618btBSgpw1V49QKVrbLyIrh8Dt7KILZje6i\n"
          + "jhRcne39jq8c7y7ZSosFD4lk9G0eoNDCpD4N2mGCrb9PbtF1tnQiV4Wb8i86QX7P\n"
          + "H52JMXteU51YevFrnhMT4EUU/6ZLqLP/K4Mh+IEcs/sCLI9kTnCkuAovv+5gSrtz\n"
          + "eQkeqObFx038AoNma0DAeThwAoIEoTa/XalWjreY00kDi9sMEeA0ReeEfLUGnHXP\n"
          + "KKxgHHeZ2VghDdvLIm5Rr++fHeR7Bzhz1tP5dFa+3ghQgudKKYss1I9LMJMVXzZs\n"
          + "j6YBxq+FjfoywISRsqKYh/kDNZSaXW7apnmIKjqV1r9tlwoiH0udPYy/OEr4GqyV\n"
          + "4rMpTgR4msg3J6XcBFWflq9B2KBTUW/u7rxSdG62qygZ4JEIcQ2DXwEfpjBlhyrT\n"
          + "NNXN/7KyMQUH6S/Jk64xfal/TzCc2vD2ftmdkCFVdgg4SflTskbX/ts/22dnmFCl\n"
          + "rUBOZBR/t89Pau3dBa+0uDSWjR/ogBSWDc5dlCI2Um4SpHjWnl++aXAxCzCMBoRQ\n"
          + "GM/HsqtDChOmsax7sCzMuz2RGsLxEGhhP74Cm/3OAs9c04lQ7XLIOUTt+8dWFa+H\n"
          + "+GTAUfPFVFbFQShjpAwG0dq1Yr3/BXG408ORe70wCIC7pemYI5uV+pG31kFtTzmL\n"
          + "OtvNMJg+01krTZ731CNv0A9Q2YqlOiNaxBcnIPd9lhcmcpgM/o/3pacCeD7cK6Mb\n"
          + "IlkBWhEvx/RoqcL5RkA5AC0w72eLTLeYvBFiFr96mnwYugO3tY/QdRXTEVBJ02FL\n"
          + "56B+dEMAdQ3x0sWHUziQWer8PXhczdMcB2SL7cA6XDuK1G0GTVnBPVc3Ryn8TilT\n"
          + "YuKlGRIEUwQovBUir6KP9f4WVeMEylvIwnrQ4MajndTfKJVsFLOMyTaCzv5AK71e\n"
          + "gtKcRk5E6103tI/FaN/gzG6OFrrqBeUTVZDxkpTnPoNnsCFtu4FQMLneVZE/CAOc\n"
          + "QjUcWeVRXdWvjgiaFeYl6Pbe5jk4bEZJfXomMoh3TeWBp96WKbQbRCQUH5ePuDMS\n"
          + "CO/ew8bg3jm8VwY/Pc1sRwNzwIiR6inLx8xtZIO4iJCDrOhqp7UbHCz+birRjZfO\n"
          + "NvvFbqQvrpfmp6wRSGRHjDZt8eux57EakJhQT9WXW98fSdxwACtjwXOanSY/utQH\n"
          + "P2qfbCuK9LTDMqEDoM/6Xe6y0GLKPCFf02ACa+fFFk9KRCTvdJSIBNZvRkh3Msgg\n"
          + "LHlUeGR7TqcdYnwIYCTMo1SkHwh3s48Zs3dK0glcjaU7Bp4hx2ri0gB+FnGe1ACA\n"
          + "0zT32lLp9aWZBDnK8IOpW4M/Aq0QoIwabQ8mDAByhb1KL0dwOlrvRlKH0lOxisIl\n"
          + "FDFiEP9WaBSxD4eik9bxmdPDlZmQ0MEmi09Q1fn877vyN70MKLgBgtZll0HxTxC/\n"
          + "uyG7oSq2IKojlvVsBoa06pAXmQIkIWsv6K12xKkUju+ahqNjWmqne8Hc+2+6Wad9\n"
          + "/am3Uw3AyoZIyNlzc44Burjwi0kF6EqkZBvWAkEM2XUgJl8vIx8rNeFesvoE0r2U\n"
          + "1ad6uvHg4WEBCpkAh/W0bqmIsrwFEv2g+pI9rdbEXFMB0JSDZzJltasuEPS6Ug9r\n"
          + "utVkpcPV4nvbCA99IOEylqMYGVTDnGSclD6+F99cH3quCo/hJsR3WFpdTWSKDQCL\n"
          + "avXozTG+aakpbU8/0l7YbyIeS5P2X1kplnUzYkuSNXUMMHB1ULWFNtEJpxMcWlu+\n"
          + "SlcVVnwSU0rsdmB2Huu5+uKJHHdFibgOVmrVV93vc2cZa3In6phw7wnd/seda5MZ\n"
          + "poebUgXXa/erpazzOvtZ0X/FTmg4PWvloI6bZtpT3N4Ai7KUuFgr0TLNzEmVn9vC\n"
          + "HlJyGIDIrQNSx58DpDu9hMTN/cbFKQBeHnzZo0mnFoo1Vpul3qgYlo1akUZr1uZO\n"
          + "IL9iQXGYr8ToHCjdd+1AKCMjmLUvvehryE9HW5AWcQziqrwRoGtNuskB7BbPNlyj\n"
          + "8tU4E5SKaToPk+ecRspdWm3KPSjKUK0YvRP8pVBZ3ZsYX3n5xHGWpOgbIQS8RgoF\n"
          + "HgLy6ERP\n"
          + "-----END PUBLIC KEY-----\n";

  // From:
  // https://datatracker.ietf.org/doc/html/rfc9881#name-example-public-keys
  private static final String ML_DSA_87_PUBLIC_KEY_PEM =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIKMjALBglghkgBZQMEAxMDggohAJeSvOwvJDBoaoL8zzwvX/Zl53HXq0G5AljP\n"
          + "p+kOyXEkpzsyO5uiGrZNdnxDP1pSHv/hj4bkahiJUsRGfgSLcp5/xNEV5+SNoYlt\n"
          + "X+EZsQ3N3vYssweVQHS0IzblKDbeYdqUH4036misgQb6vhkHBnmvYAhTcSD3B5O4\n"
          + "6pzA5ue3tMmlx0IcYPJEUboekz2xou4Wx5VZ8hs9G4MFhQqkKvuxPx9NW59INfnY\n"
          + "ffzrFi0O9Kf9xMuhdDzRyHu0ln2hbMh2S2Vp347lvcv/6aTgV0jm/fIlr55O63dz\n"
          + "ti6Phfm1a1SJRVUYRPvYmAakrDab7S0lYQD2iKatXgpwmCbcREnpHiPFUG5kI2Hv\n"
          + "WjE3EvebxLMYaGHKhaS6sX5/lD0bijM6o6584WtEDWAY+eBNr1clx/GpP60aWie2\n"
          + "eJW9JJqpFoXeIK8yyLfiaMf5aHfQyFABE1pPCo8bgmT6br5aNJ2K7K0aFimczy/Z\n"
          + "x7hbrOLO06oSdrph7njtflyltnzdRYqTVAMOaru6v1agojFv7J26g7UdQv0xZ/Hg\n"
          + "+QhV1cZlCbIQJl3B5U7ES0O6fPmu8Ri0TYCRLOdRZqZlHhFs6+SSKacGLAmTH3Gr\n"
          + "0ik/dvfvwyFbqXgAA35Y5HC9u7Q8GwQ56vecVNk7RKrJ7+n74VGHTPsqZMvuKMxM\n"
          + "D+d3Xl2HDxwC5bLjxQBMmV8kybd5y3U6J30Ocf1CXra8LKVs4SnbUfcHQPMeY5dr\n"
          + "UMcxLpeX14xbGsJKX6NHzJFuCoP1w7Z1zTC4Hj+hC5NETgc5dXHM6Yso2lHbkFa8\n"
          + "coxbCxGB4vvTh7THmrGl/v7ONxZ693LdrRTrTDmC2lpZ0OnrFz7GMVCRFwAno6te\n"
          + "9qoSnLhYVye5NYooUB1xOnLz8dsxcUKG+bZAgBOvBgRddVkvwLfdR8c+2cdbEenX\n"
          + "xp98rfwygKkGLFJzxDvhw0+HRIhkzqe1yX1tMvWb1fJThGU7tcT6pFvqi4lAKEPm\n"
          + "Rba5Jp4r2YjdrLAzMo/7BgRQ998IAFPmlpslHodezsMs/FkoQNaatpp14Gs3nFNd\n"
          + "lSZrCC9PCckxYrM7DZ9zB6TqqlIQRDf+1m+O4+q71F1nslqBM/SWRotSuv/b+tk+\n"
          + "7xqYGLXkLscieIo9jTUp/Hd9K6VwgB364B7IgwKDfB+54DVXJ2Re4QRsP5Ffaugt\n"
          + "rU+2sDVqRlGP/INBVcO0/m2vpsyKXM9TxzoISdjUT33PcnVOcOG337RHu070nRpx\n"
          + "j2Fxu84gCVDgzpJhBrFRo+hx1c5JcxvWZQqbDKly2hxfE21Egg6mODwI87OEzyM4\n"
          + "54nFE/YYzFaUpvDO4QRRHh7XxfI6Hr/YoNuEJFUyQBVtv2IoMbDGQ9HFUbbz96mN\n"
          + "KbhcLeBaZfphXu4WSVvZBzdnIRW1PpHF2QAozz8ak5U6FT3lO0QITpzP9rc2aTkm\n"
          + "2u/rstd6pa1om5LzFoZmnfFtFxXMWPeiz7ct0aUekvglmTp0Aivn6etgVGVEVwlN\n"
          + "FJKPICFeeyIqxWtRrb7I2L22mDl5p+OiG0S10VGMqX0LUZX1HtaiQ1DIl0fh7epR\n"
          + "tEjj6RRwVM6SeHPJDbOU2GiI4H3/F3WT1veeFSMCIErrA74jhq8+JAeL0CixaJ9e\n"
          + "FHyfRSyM6wLsWcydtjoDV2zur+mCOQI4l9oCNmMKU8Def0NaGYaXkvqzbnueY1dg\n"
          + "8JBp5kMucAA1rCoCh5//Ch4b7FIgRxk9lOtd8e/VPuoRRMp4lAhS9eyXJ5BLNm7e\n"
          + "T14tMx+tX8KC6ixH6SMUJ3HD3XWoc1dIfe+Z5fGOnZ7WI8F10CiIxR+CwHqA1UcW\n"
          + "s8PCvb4unwqbuq6+tNUpNodkBvXADo5LvQpewFeX5iB8WrbIjxpohCG9BaEU9Nfe\n"
          + "KsJB+g6L7f9H92Ldy+qpEAT40x6FCVyBBUmUrTgm40S6lgQIEPwLKtHeSM+t4ALG\n"
          + "LlpJoHMas4NEvBY23xa/YH1WhV5W1oQAPHGOS62eWgmZefzd7rHEp3ds03o0F8sO\n"
          + "GE4p75vA6HR1umY74J4Aq1Yut8D3Fl+WmptCQUGYzPG/8qLI1omkFOznZiknZlaJ\n"
          + "6U25YeuuxWFcvBp4lcaFGslhQy/xEY1GB9Mu+dxzLVEzO+S00OMN3qeE7Ki+R+dB\n"
          + "vpwZYx3EcKUu9NwTpPNjP9Q014fBcJd7QX31mOHQ3eUGu3HW8LwX7HDjsDzcGWXL\n"
          + "Npk/YzsEcuUNCSOsbGb98dPmRZzBIfD1+U0J6dvPXWkOIyM4OKC6y3xjjRsmUKQw\n"
          + "jNFxtoVRJtHaZypu2FqNeMKG+1b0qz0hSXUoBFxjJiyKQq8vmALFO3u4vijnj+C1\n"
          + "zkX7t6GvGjsoqNlLeJDjyILjm8mOnwrXYCW/DdLwApjnFBoiaz187kFPYE0eC6VN\n"
          + "EdX+WLzOpq13rS6MHKrPMkWQFLe5EAGx76itFypSP7jjZbV3Ehv5/Yiixgwh6CHX\n"
          + "tqy0elqZXkDKztXCI7j+beXhjp0uWJOu/rt6rn/xoUYmDi8RDpOVKCE6ACWjjsea\n"
          + "q8hhsl68UJpGdMEyqqy34BRvFO/RHPyvTKpPd1pxbOMl4KQ1pNNJ1yC88TdFCvxF\n"
          + "BG/Bofg6nTKXd6cITkqtrnEizpcAWTBSjrPH9/ESmzcoh6NxFVo7ogGiXL8dy2Tn\n"
          + "ze4JLDFB+1VQ/j0N2C6HDleLK0ZQCBgRO49laXc8Z3OFtppCt33Lp6z/2V/URS4j\n"
          + "qqHTfh2iFR6mWNQKNZayesn4Ep3GzwZDdyYktZ9PRhIw30ccomCHw5QtXGaH32CC\n"
          + "g1k1o/h8t2Kww7HQ3aSmUzllvvG3uCkuJUwBTQkP7YV8RMGDnGlMCmTj+tkKEfU0\n"
          + "citu4VdPLhSdVddE3kiHAk4IURQxwGJ1DhbHSrnzJC8ts/+xKo1hB/qiKdb2NzsH\n"
          + "8205MrO9sEwZ3WTq3X+Tw8Vkw1ihyB3PHJwx5bBlaPl1RMF9wVaYxcs4mDqa/EJ4\n"
          + "P6p3OlLJ2CYGkL6eMVaqW8FQneo/aVh2lc1v8XK6g+am2KfWu+u7zaNnJzGYP4m8\n"
          + "WDHcN8PzxcVvrMaX88sgvV2629cC5UhErC9iaQH+FZ25Pf1Hc9j+c1YrhGwfyFbR\n"
          + "gCdihA68cteYi951y8pw0xnTLODMAlO7KtRVcj7gx/RzbObmZlxayjKkgcU4Obwl\n"
          + "kWewE9BCM5Xuuaqu4yBhSafVUNZ/xf3+SopcNdJRC2ZDeauPcoVaKvR6vOKmMgSO\n"
          + "r4nly0qI3rxTpZUQOszk8c/xis/wev4etXFqoeQLYxNMOjrpV5+of1Fb4JPC0p22\n"
          + "1rZck2YeAGNrWScE0JPMZxbCNC6xhT1IyFxjrIooVEYse3fn470erFvKKP+qALXT\n"
          + "SfilR62HW5aowrKRDJMBMJo/kTilaTER9Vs8AJypR8Od/ILZjrHKpKnL6IX3hvqG\n"
          + "5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==\n"
          + "-----END PUBLIC KEY-----\n";

  @Test
  public void read_oneMlDsa65PublicKey_shouldWork() throws Exception {
    byte[] expectedKeyBytes =
        Hex.decode(
            "48683d91978e31eb3dddb8b0473482d2b88a5f62594"
                + "9fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d"
                + "51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd515"
                + "11f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c"
                + "2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3ce"
                + "a8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173f"
                + "ce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa4515"
                + "5d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a459"
                + "06eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee7"
                + "2a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e168"
                + "12b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b"
                + "8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f263782"
                + "22fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b288"
                + "2d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dd"
                + "a6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16"
                + "b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfe"
                + "e604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568"
                + "eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbc"
                + "b226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b309"
                + "3155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882"
                + "a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5d"
                + "c04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63"
                + "065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d9"
                + "0215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aedd"
                + "d05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b3"
                + "08c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029"
                + "bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c541286"
                + "3a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d64"
                + "16d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac417272"
                + "0f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f"
                + "9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115"
                + "049d3614be7a07e744300750df1d2c58753389059eafc3d785ccdd31c07648be"
                + "dc03a5c3b8ad46d064d59c13d57374729fc4e295362e2a5191204530428bc152"
                + "2afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cef"
                + "e402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19"
                + "294e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089"
                + "a15e625e8f6dee639386c46497d7a263288774de581a7de9629b41b4424141f9"
                + "78fb8331208efdec3c6e0de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6"
                + "483b8889083ace86aa7b51b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac1"
                + "14864478c366df1ebb1e7b11a9098504fd5975bdf1f49dc70002b63c1739a9d2"
                + "63fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca3c215fd360026"
                + "be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d627c0"
                + "86024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e167"
                + "19ed40080d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260"
                + "c007285bd4a2f47703a5aef465287d253b18ac22514316210ff566814b10f87a"
                + "293d6f199d3c3959990d0c1268b4f50d5f9fcefbbf237bd0c28b80182d665974"
                + "1f14f10bfbb21bba12ab620aa2396f56c0686b4ea9017990224216b2fe8ad76c"
                + "4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d97"
                + "3738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35e15eb2f"
                + "a04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923da"
                + "dd6c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7"
                + "d20e13296a3181954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d6"
                + "48a0d008b6af5e8cd31be69a9296d4f3fd25ed86f221e4b93f65f59299675336"
                + "24b9235750c30707550b58536d109a7131c5a5bbe4a5715567c12534aec76607"
                + "61eebb9fae2891c774589b80e566ad557ddef7367196b7227ea9870ef09ddfec"
                + "79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d6be5a08e9b6"
                + "6da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f0"
                + "3a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a914"
                + "66bd6e64e20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475"
                + "b9016710ce2aabc11a06b4dbac901ec16cf365ca3f2d53813948a693a0f93e79"
                + "c46ca5d5a6dca3d28ca50ad18bd13fca55059dd9b185f79f9c47196a4e81b210"
                + "4bc460a051e02f2e8444f");
    assertThat(expectedKeyBytes.length * 8).isEqualTo(PemKeyType.ML_DSA_65.keySizeInBits);
    MlDsaParameters expectedParameters = MlDsaParameters.create(
          MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ML_DSA_65_PUBLIC_KEY_PEM, PemKeyType.ML_DSA_65)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
    MlDsaPublicKey publicKey = (MlDsaPublicKey) handle.getAt(0).getKey();
    assertThat(publicKey.getParameters()).isEqualTo(expectedParameters);
    assertThat(publicKey.getSerializedPublicKey().toByteArray()).isEqualTo(expectedKeyBytes);
  }

  @Test
  public void read_oneMlDsa87PublicKey_shouldWork() throws Exception {
    byte[] expectedKeyBytes =
        Hex.decode(
            "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab4"
                + "1b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46"
                + "a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb3079"
                + "54074b42336e52836de61da941f8d37ea68ac8106fabe19070679af600853712"
                + "0f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f"
                + "21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba"
                + "1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9"
                + "e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f68"
                + "8a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861c"
                + "a85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fa"
                + "d1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0"
                + "a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba6"
                + "1ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42f"
                + "d3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912"
                + "ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba9780"
                + "0037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64c"
                + "bee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e7"
                + "1fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24"
                + "a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da5"
                + "1db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4"
                + "c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a2"
                + "8501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c"
                + "75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d3"
                + "2f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb03"
                + "3328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06"
                + "b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee"
                + "3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3"
                + "d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f9"
                + "15f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a084"
                + "9d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926"
                + "106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b"
                + "384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db842"
                + "4553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee1"
                + "6495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b"
                + "736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd"
                + "1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b5"
                + "1adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c8974"
                + "7e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e1"
                + "52302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9"
                + "db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7"
                + "b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df"
                + "1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c4"
                + "7e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07"
                + "a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec"
                + "05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762d"
                + "dcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48c"
                + "fade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4"
                + "bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663"
                + "be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662"
                + "927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef"
                + "9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc1"
                + "3a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03"
                + "cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e"
                + "9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6"
                + "ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be2"
                + "8e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0"
                + "dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8"
                + "c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60"
                + "c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aa"
                + "e7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c13"
                + "2aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf13"
                + "7450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f"
                + "7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0"
                + "dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95"
                + "fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b"
                + "59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d"
                + "0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad"
                + "90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74"
                + "ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64e"
                + "add7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983"
                + "a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff"
                + "172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc69"
                + "7f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846"
                + "c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad4557"
                + "23ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaa"
                + "ee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce"
                + "2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa"
                + "1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b59270"
                + "4d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28f"
                + "faa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c0"
                + "09ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a97407"
                + "3326b31212aece0a34a60");
    assertThat(expectedKeyBytes.length * 8).isEqualTo(PemKeyType.ML_DSA_87.keySizeInBits);
    MlDsaParameters expectedParameters =
        MlDsaParameters.create(
            MlDsaParameters.MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX);

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ML_DSA_87_PUBLIC_KEY_PEM, PemKeyType.ML_DSA_87)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
    MlDsaPublicKey publicKey = (MlDsaPublicKey) handle.getAt(0).getKey();
    assertThat(publicKey.getParameters()).isEqualTo(expectedParameters);
    assertThat(publicKey.getSerializedPublicKey().toByteArray()).isEqualTo(expectedKeyBytes);
  }

  @Test
  public void buildPublicKeysetHandle_invalidMlDsa65PublicKey_isIgnored() throws Exception {
    // has the correct preamble, but is not long enough.
    String invalid1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIHsjALBglghkgBZQMEAxIDggehAEhoPZGXjjHrPd24sEc0gtK4il9iWUn9j1il\n"
          + "YeaWvUwn0Fs427Lt8B5mTv2Bvh6ok2iM5oqi1RxZWPi7xutOie5n0sAyCVTVchLK\n"
          + "xyKf8dbq8DkovVFRH42I2EdzbH3icw1ZeOVBBxMWCXiGdxG/VTmgv8TDUMK+Vyuv\n"
          + "DuLi+xbM/qCAKNmaxJrrt1k33c4RHNq2L/886ouiIz0eVvvFxaHnJt5j+t0q8Bax\n"
          + "GRd/o9lxotkncXP85VtndFrwt8IdWX2+uT5qMvNBxJpai+noJQiNHyqkUVXWyK4V\n"
          + "-----END PUBLIC KEY-----\n";
    // does not have the whole preamble.
    String invalid2 =
      "-----BEGIN PUBLIC KEY-----\nMIIHsjALBglg\n-----END PUBLIC KEY-----\n";

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(invalid1, PemKeyType.ML_DSA_65) // is ignored
            .addPem(invalid2, PemKeyType.ML_DSA_65) // is ignored
            .addPem(ML_DSA_65_PUBLIC_KEY_PEM, PemKeyType.ML_DSA_65)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);
  }

  public static final class PemTestVector {
    public PemTestVector(String pem, PemKeyType pemKeyType, byte[] message, byte[] signature) {
      this.pem = pem;
      this.pemKeyType = pemKeyType;
      this.message = message;
      this.signature = signature;
    }

    public final String pem;
    public final PemKeyType pemKeyType;
    public final byte[] message;
    public final byte[] signature;
  }

  @DataPoints("pemTestVectors")
  public static final PemTestVector[] pemTestVectors = {
    // from wycheproof/testvectors_v1/rsa_pkcs1_2048_sig_gen_test.json,
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAorRRoH0KpfluRVZxUTVQ\n"
            + "UUqKW0YuvvcXCU+h/ugiJOY3+XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQ\n"
            + "l7WrOTGJ25JRLtincRoSU/rNIPecFegkfz0+QuRuSMmOJUov6XZTE6A+/48X4aAp\n"
            + "OXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7O\n"
            + "a0wDFFtdNJXU7VQR64eNrwX9evw+Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg\n"
            + "2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K5\n"
            + "1QIDAQAB\n"
            + "-----END PUBLIC KEY-----",
        PemKeyType.RSA_SIGN_PKCS1_2048_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "264491e844c119f14e425c03282139a558dcdaeb82a4628173cd407fd319f9076eaebc0dd87a1c22e4d17839096886d58a9d5b7f7aeb63efec56c45ac7bead4203b6886e1faa90e028ec0ae094d46bf3f97efdd19045cfbc25a1abda2432639f9876405c0d68f8edbf047c12a454f7681d5d5a2b54bd3723d193dbad4338baad753264006e2d08931c4b8bb79aa1c9cad10eb6605f87c5831f6e2b08e002f9c6f21141f5841d92727dd3e1d99c36bc560da3c9067df99fcaf818941f72588be33032bad22caf6704223bb114d575b6d02d9d222b580005d930e8f40cce9f672eebb634a20177d84351627964b83f2053d736a84ab1a005f63bd5ba943de6205c")),
    // from wycheproof/testvectors_v1/rsa_pkcs1_3072_sig_gen_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxv4jeSVmAjwmUofFrG9x\n"
            + "VBwJlNEdBZ7mQDmG76IcJLUb2R2IYvnfeaTjKOPifIPfJgslqbQ0IK/8RLUejXUl\n"
            + "tvKcNypAUQRzIAdSemLtgvrHP0iSqA4JaCpBpYzTRwF/O+fYATNPktkyGq/VO1G/\n"
            + "+r/HUs/Mrgse4Dva/55CjMHBF/GslrT+I/jCPmOBGGpm/VkokzmuVcS82tv/hKva\n"
            + "pTIkDU4dKLLQSB2t07JGVXyo/hgJKBdzCznm7jeP/MhbGf/ckWqbmRprZtSpx7q1\n"
            + "9eejciEBFC56QQjBXVc7FSieB+RurqB7QsKry6Mw6ZVUtGVhZbtMDbK2OToH7KV1\n"
            + "xRqTxOFb2w90eQlEfj7+NMZ8qJVLUw5WogobbYTUXtG806pY7AbxhO5YV6qoGeHM\n"
            + "qaJvTijWuXfTORbbmJbSUtGvp2Lih8sNOEzHW/5T9Oki0C3QpIHAQuLTBrSzwYk3\n"
            + "HldbJeAAWhZM9p3Ql25NW+R2gG6mvmCE5xq09axcGxIDAgMBAAE=\n"
            + "-----END PUBLIC KEY-----",
        PemKeyType.RSA_SIGN_PKCS1_3072_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "5819a699691c01a7f35f0bb1831a1cb65631ef693f7c9ef89f1e8460ee2ec312f6fd38fe382b3bf4db8f5d208146c32c5ed2d3b13105743767a73529bfddb5753c8cc13148d41db97f69ea1dee0ef1e1de990ff565f633bd3cfd315a7dafc70aa7f27d4f6486a2f1e2711e7919c5c73c518069338c0ac984d75f58b00fb0eee0f7da6c9c84d97955137417df8f20c02b7893b5cd929ba37f6b3278a1bd35748e14086c5f7100abf2edebeab5f767bb83d999a61cc27531bb67e44a92004fba9944b9c5f770bc66671d2efc74e01fbbd2885c5175a1fd72b91937c324b8d99d3592bfb73efb9641b87949266de441b61d180e141de510ae0cdefc2160df918c08c53799f050ca4eeb3a8b6b5ed35b8b59d3acd13a600a8a137eb1b8c1abbf55f3e99cf52d7092d1e3acc08583b04aa25a052668bc982abf060ffb17c1782daf76fbd69e7fc9510c5c6a68bd525719be5b81d0f2a8b961f1aeac7dc13aeeeef9986c7a47b34f8b96167d79f7ec458fef7345c1c31bba599d09b3fe33e738bc7da1")),
    // from wycheproof/testvectors_v1/rsa_pkcs1_4096_sig_gen_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlWNT7LdWGUXcVUTkYCRm\n"
            + "B4yT8oUHcB/9OeKpgTyKyHQOatYclV1ITlE7Pc6lJ+ABoBjuLCB8GAapZ2MoAjbN\n"
            + "PIIN/3mDfJtwnLS1ItPdvJGSJCJZxDvnXqJE03zPqKTHUCSiz3zHboQuppzHyhIn\n"
            + "QFsHAEc4elBo5JduS47V+arde02wJPu4172KBA2PZhDBxusdS2Bt/RgiNdA2CIAw\n"
            + "TVp1BgOvDEJLjI5tvBLDaX0tYJyXVH53Ti42LqltFpDclDIRLFNSWLPbLEwyrVEN\n"
            + "bAetB4g1eIOGnvuLYpKYckhHklz0KzQ4a+cA8CkD21hSJ2vuI3CUHzl73DkF4wlk\n"
            + "oLXnNgJwM0CWDD7WB4JjthHxl5Vf7M5LmjLkPNHS5eh8TOtl7ciFOn7jHSjhblrf\n"
            + "+4rHt2D7/GPV8XT00JNkYduxLJZKa21s7nUuX8oatKn9I43T6IYKHXY9IBn557me\n"
            + "12ZtTgOHEPkOAJO8VmmH1sAJL1cTducFs0LQZsVObiV4knuSwfCSjeROmm4fSbkH\n"
            + "xqpPYF7Jw5jVXfgcZzc7A8yBEBYvtBf5b9MhBIZH38uzkkVRFc2RLqgzUYU+ahhS\n"
            + "hGSIQq3L0l5nF0o7k7imTOLOneDoV3uLZizjLiVleCZl3Tjlu1/MT+EuQyDat3c7\n"
            + "VFoJxtOdnbrUWfIfPmJO5u0CAwEAAQ==\n"
            + "-----END PUBLIC KEY-----",
        PemKeyType.RSA_SIGN_PKCS1_4096_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "43929c2fb0986fc4570a3ee7f6701b96a78ec9297a997415a142ae539031c0e196add5e4c6ec572de0a2b109cf23a42567ebe98f42cf312d07538e4a32b0f20403b662c652ba9e3d6e38a625d6b5e91cce5c810d7a02262338e144a57db4ac4debfc536e8eaca7fe08022a2f64741d66d25e3010f2fd259d4c6b00582584bbbdcde4266d86eddfd0443ff24b06cf7ade6d733c637a48a398dbb28355ffb9bd21a49de6b345ef635b68d917b5bfcb9016f7c64c444dc0036ecab8f59b0d29098facca02335df44db87d30d02f08553ffd0379b33d13d09a385cae7d63b6db52e9b1eb8fd549e0e1e18210de1d3e9527547e5c72f816eb36288b09d96db772f955ca46fc8cbdb6eea93c841e1075c00c3c45e9442d28095136cc5ce8212ed8c60c9668898ab5d64734d4d0f2311f104cf8a732e6d88fb2064cb57bd54d3cdef7c11c840ecb238466c747289233a317b73785778ff4349949da47c9b4b2dc9f89bd1fe7e98b582500dfc05dba3fa410cca66acd854669940543c22ed1038eac7f0212b9ce4aedba0eb15ea1e75a73c45c1ae03fd241662e9cb89b051939c468db3a0adab822617b5bc669d1e0226cf6b475445d9d5e77ef54ed646cd81f0952b949b7f4f37381ba6427e060966467a76e1d9261a5fe8c68398a89eb5025cc39339885b6c33dde898a159f0af4acc81461fae37f5f4c61de4a888dc4f6b1e2b7336f")),
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyadlwmYbRnTP80gOml5G\n"
            + "KtCtL8m8b772KEezET0gmR9lOWeXHCglJ1P1+6zOASwqirWSkU0mnvr6ck+kuSDj\n"
            + "QJMMEG97Nvec6/DmLojg5HaIjp8OIhhqzbbEUjojK2W0/yzCLcRPilWVJ9edfNfc\n"
            + "83cyEve7mqEzwxFlzGY2kL8SPXOSPIOJKcyv7lnWxwlbjUp0uvLRksmk6HxOErxY\n"
            + "ATB4sop3iegunzHeH01qKqboBjK+jkvfJj6NSbCUFvsZxIjAetivciq3kYKyMCin\n"
            + "HgZdAkEqnuvEbX2PTgPXkjjYwMtKl6mhIA67bsZAQuvsytlWdSbu7xLBfZTBBJyI\n"
            + "mXC5bpTMNTFyomiknF6L7hPBWznexE8sehqjenoLb3IpCsraMrHYrx/D3IqJSHuo\n"
            + "E0fL6xNQkl0w+SOVgQa0mVnIcefB26VdoHcuNiz4Yh14YQhouJThbl3+yWh0qTpM\n"
            + "83m0fn4xjOMVBm1w7jk4FApgFI8gUIXO+KdwDKPFPVKldWpjs7FvFTBithJipoSW\n"
            + "IQyL5O8/kCnKDqDjs6DV1tIm7bv0Ta+PBF3Cht7TxOxNtrRTRwefM+r5jjyVtLYO\n"
            + "ee9KMJP+7FQ3A0Irp0oRhRHCGTtU/otjOGbtLHBcy8bn2dNlaAnsPTNW50AKlkjs\n"
            + "N1BQQePjGvHALu/pJKZwR9MCAwEAAQ==\n"
            + "-----END PUBLIC KEY-----",
        PemKeyType.RSA_SIGN_PKCS1_4096_SHA512,
        Hex.decode("54657374"),
        Hex.decode(
            "46eaa4624a4d2c1f1043eb3d17b48d977819a8796f48f20174c50da624c657e64d3154dcfa2a5b1d8c6d2ed07cf1f1c19aaa611d6466f7e7ec73df5ee786573adc5a9e3c1d0a25559dad282db26e889807764115a05a23959acf48d23b3b33a93d8b6c7de3ee446f113eef96055d285fdfd27888e569c50f022d5e8abafc874dd5a61df6258e85268bff66cc5643107f7d9097496caedc185b37311ab6979f273e5670f143146b68e44b49389554772c1ca7bb7a12fcf67d67a1fd0c245bb4cbb924276ae756098599392cde076a1c0edc8096d9125e5a5d30c2a93d00fe2e0362e98592c8fd31ab5b4c3b34e65d38ca0c25874eb394e04969982b70932616b75ee2912c6a07f20ec70e52be630ebe024c0622aed125e00bc84980416b80cba7752eb90af2b8215c4b559880d2e1c577b7374531038083725d23d02d4fa5d8b5a4c68e9ea5e11fe2d9e03c1b8a4db0b053097b5a175b1131e8beef5d559bcc3f17ed2e6f6304c0e4650a2bb675aa8de44af8a2e301734584eea145c4b389f6180e6395412ae70e57f488ed15d45895be580bd87cd916b8f20e46ad2fff0367dda54266778bb444c6e4fdd45fa62cae3aeb54b6a7a6b4d8068e3a4d0730f0260340a6c32c3c5d33f514612c941bb63d730df5584933e12546500495b5ed3ba3631a3db871d17353d4c16676a0332ba4c4c4c68cdb6ff21ff737ee249be153c1d9")),
    // from wycheproof/testvectors_v1/rsa_pss_2048_sha256_mgf1_32_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAorRRoH0KpfluRVZxUTVQ\n"
            + "UUqKW0YuvvcXCU+h/ugiJOY3+XRtP3yv0xh42AMltu9aFwD2WQO0aUKeidbqyIRQ\n"
            + "l7WrOTGJ25JRLtincRoSU/rNIPecFegkfz0+QuRuSMmOJUov6XZTE6A+/48X4aAp\n"
            + "OXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7O\n"
            + "a0wDFFtdNJXU7VQR64eNrwX9evw+Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg\n"
            + "2Pn4Xnl1AF2bwixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K5\n"
            + "1QIDAQAB\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.RSA_PSS_2048_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "401eb03cdb47ca88033e3030f6bdecbac8f5c8fc1dd6a13d23d379ed9a2b309891d13d74fea9d21d159b9e6d8f37efa2489962e24555f56dd434ff1d31ce4f9f5abd3f22cbea8b691d6a11e44efb83e2bca155e6a164325e0fde2a8865afd5c9f51161a9d615f62af7ec2e31b3e5ab649c164490d31d88cfae35b84aea7925690f929a144b6d2f48e8fb894a52deecd1b9a6496990c4ecf1588699a42cacd10c53af350514e4291ea9a058e77f101e32c1c0cefa61d945f7bc931f8bd19e7ba3169358a60e5a8b0123bc3199b9fdcafe8e519c41ba675491a27b85e44ef2d77277c10fe107293c8290186913bc9a99b640d8da041b64f31eab1d35920985f4a5")),
    // from wycheproof/testvectors_v1/rsa_pss_3072_sha256_mgf1_32_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxv4jeSVmAjwmUofFrG9x\n"
            + "VBwJlNEdBZ7mQDmG76IcJLUb2R2IYvnfeaTjKOPifIPfJgslqbQ0IK/8RLUejXUl\n"
            + "tvKcNypAUQRzIAdSemLtgvrHP0iSqA4JaCpBpYzTRwF/O+fYATNPktkyGq/VO1G/\n"
            + "+r/HUs/Mrgse4Dva/55CjMHBF/GslrT+I/jCPmOBGGpm/VkokzmuVcS82tv/hKva\n"
            + "pTIkDU4dKLLQSB2t07JGVXyo/hgJKBdzCznm7jeP/MhbGf/ckWqbmRprZtSpx7q1\n"
            + "9eejciEBFC56QQjBXVc7FSieB+RurqB7QsKry6Mw6ZVUtGVhZbtMDbK2OToH7KV1\n"
            + "xRqTxOFb2w90eQlEfj7+NMZ8qJVLUw5WogobbYTUXtG806pY7AbxhO5YV6qoGeHM\n"
            + "qaJvTijWuXfTORbbmJbSUtGvp2Lih8sNOEzHW/5T9Oki0C3QpIHAQuLTBrSzwYk3\n"
            + "HldbJeAAWhZM9p3Ql25NW+R2gG6mvmCE5xq09axcGxIDAgMBAAE=\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.RSA_PSS_3072_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "22915cfa1d7dd30f50b4c0e4cee42c5f0aa1b7a6644f8a11e611b2db042b122af8211ffc1dc220b435d8919cf64d715b54ff8a762f702b365cbdab455509b97d9b310011467d4186647b957e2efa404aed3b84840529bdef7746348385a1c6a2ecdb88d1cc2b40b36c346386739c39d2815938e463a35348426f17d32d633b873d6124d8b49a726743af7c0e56d63394155b63089c63ed8897f8af2a2260d33499afab11c911faa754ced5acdac2de571f39c2768716e4308244a99d1e65da7061d2feb8ec8b4e517bd5e19cac626698479ab2019257cf83ad7b641db2345b38006d63f84b41772b90037778389cc30ed6aba6af212d9326792af746d7bca9211fa344fdc2798a490aed3a2840620c2a85e3d9b9c38f2330072663e16dd26bc414c7d68f6b11d2cd3e0387c1834c5e2262a9e2dc1bf7c0108b4e2052566c7a941ef6b38c8687fd7abe6add2b745c2c2d680ae3e5646ce2e717ef9899c7f3fb1e3088e8c0587d86546f752771819595a7a3d422820ceaa12e3ee671a456dac673")),
    // from wycheproof/testvectors_v1/rsa_pss_4096_sha256_mgf1_32_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlWNT7LdWGUXcVUTkYCRm\n"
            + "B4yT8oUHcB/9OeKpgTyKyHQOatYclV1ITlE7Pc6lJ+ABoBjuLCB8GAapZ2MoAjbN\n"
            + "PIIN/3mDfJtwnLS1ItPdvJGSJCJZxDvnXqJE03zPqKTHUCSiz3zHboQuppzHyhIn\n"
            + "QFsHAEc4elBo5JduS47V+arde02wJPu4172KBA2PZhDBxusdS2Bt/RgiNdA2CIAw\n"
            + "TVp1BgOvDEJLjI5tvBLDaX0tYJyXVH53Ti42LqltFpDclDIRLFNSWLPbLEwyrVEN\n"
            + "bAetB4g1eIOGnvuLYpKYckhHklz0KzQ4a+cA8CkD21hSJ2vuI3CUHzl73DkF4wlk\n"
            + "oLXnNgJwM0CWDD7WB4JjthHxl5Vf7M5LmjLkPNHS5eh8TOtl7ciFOn7jHSjhblrf\n"
            + "+4rHt2D7/GPV8XT00JNkYduxLJZKa21s7nUuX8oatKn9I43T6IYKHXY9IBn557me\n"
            + "12ZtTgOHEPkOAJO8VmmH1sAJL1cTducFs0LQZsVObiV4knuSwfCSjeROmm4fSbkH\n"
            + "xqpPYF7Jw5jVXfgcZzc7A8yBEBYvtBf5b9MhBIZH38uzkkVRFc2RLqgzUYU+ahhS\n"
            + "hGSIQq3L0l5nF0o7k7imTOLOneDoV3uLZizjLiVleCZl3Tjlu1/MT+EuQyDat3c7\n"
            + "VFoJxtOdnbrUWfIfPmJO5u0CAwEAAQ==\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.RSA_PSS_4096_SHA256,
        Hex.decode("54657374"),
        Hex.decode(
            "2b981b661e1e244b67e1892bdab545edc9ef68b50b4572a536dd4a40f31195648b8180454faa8765ba19b7ac6a59176c1a2c621e6f4131af96beb4ea47252d7617b9d8b432b5cd900f7b328b0013364a520ce46ae66a63b7181ab60b514839ec8f6bb63ec2f83a2a142d8ce532f63ebdd3f29ce26797f46f68481818ff1e00c47df1e7e8d809737307a63902c94d9c2ee5c69f1fa0602eeedab4d7f6d0032de1a8294c117ad2aa34f1175544f2bc1d466c5965ae5796bae216cee8bf7b91f9746a97749cce0388f8f443d14317e825cba2ea278045826835dfab50091cc988fc12d4913920cd625ac321df4d89175ba3f49f89d372318bc222643ab888246f8e5ad64f227be043bec3828cea0bc0229be6e71a035dca97bfe0c2f34ce03c1ee9d084d19a6d6c301168129a6589cee1119cee84e35b561d1f658b2e4f16c2b4ac2ded8ed5757ebec2d5ed59c66f7bd932d64c58af7fc16af4d3f6bc42897114c9ec537f8b7ea86752a2a26133a7b8085f4d438ba643f7a389a1c6811c2ee4eda48060d27e6299b44c8d504d280ca56ca49c246b5c4c897d3e1d352e047f735cb7e30ce87061ef267bd9c50e7de77032a162ac9a026e684bb4d0e8131a90240494418fbe471c9900a6b322306e47915f83cdd8e525566e8a71dfc869ee5c7e74d33ac8646d7c170ff82f2f3e5d319dc61cad06235145c031d03cd420fc370adb3e")),
    // from wycheproof/testvectors_v1/rsa_pss_4096_sha512_mgf1_64_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyadlwmYbRnTP80gOml5G\n"
            + "KtCtL8m8b772KEezET0gmR9lOWeXHCglJ1P1+6zOASwqirWSkU0mnvr6ck+kuSDj\n"
            + "QJMMEG97Nvec6/DmLojg5HaIjp8OIhhqzbbEUjojK2W0/yzCLcRPilWVJ9edfNfc\n"
            + "83cyEve7mqEzwxFlzGY2kL8SPXOSPIOJKcyv7lnWxwlbjUp0uvLRksmk6HxOErxY\n"
            + "ATB4sop3iegunzHeH01qKqboBjK+jkvfJj6NSbCUFvsZxIjAetivciq3kYKyMCin\n"
            + "HgZdAkEqnuvEbX2PTgPXkjjYwMtKl6mhIA67bsZAQuvsytlWdSbu7xLBfZTBBJyI\n"
            + "mXC5bpTMNTFyomiknF6L7hPBWznexE8sehqjenoLb3IpCsraMrHYrx/D3IqJSHuo\n"
            + "E0fL6xNQkl0w+SOVgQa0mVnIcefB26VdoHcuNiz4Yh14YQhouJThbl3+yWh0qTpM\n"
            + "83m0fn4xjOMVBm1w7jk4FApgFI8gUIXO+KdwDKPFPVKldWpjs7FvFTBithJipoSW\n"
            + "IQyL5O8/kCnKDqDjs6DV1tIm7bv0Ta+PBF3Cht7TxOxNtrRTRwefM+r5jjyVtLYO\n"
            + "ee9KMJP+7FQ3A0Irp0oRhRHCGTtU/otjOGbtLHBcy8bn2dNlaAnsPTNW50AKlkjs\n"
            + "N1BQQePjGvHALu/pJKZwR9MCAwEAAQ==\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.RSA_PSS_4096_SHA512,
        Hex.decode("54657374"),
        Hex.decode(
            "0f74856dae37f6bab27af25a8773ffe42690665ca130a710998e6f9f741d30dd66bbbcdcbb490b1fa69e39af6b169b28038fc4addc95aa92e2b67a76569bd3acc76ca48437c7552ca7dfd379fab037d54df496b05b431bb925416cd4dc2402faa060996d57578519c34de2386c9d0ddbeb708453e50c08a8ec182c75549e9dea0bf75fd3347b228e2f977b81c1be11c738d23ee2e58f15e803f5539e82155ba6327ab807ad6e0ea36b9a19ef68fbe7e3b55b7910f68aafc719e2106b4a3cc8adb62e38cdf43f7ab295846a56b26ed8087b2c0e9cd9c2d6cd8302aa0c26254b1db330bcac520afb932eaac07ec0604ff56f081af44994492c176298127a94d9eaccf23732ea95700ebb4b657fcdbc52ebc6bc404795f63b4f0fd2a1d6787d698d2506b7b37c1f49f8ec1563320fc017fdd76269fe61bff0089900d146e2000113ab6d8aae248344d19bf0549e8320de0f226fe46ee4c03250770d8701b7eb0e63b816f566411c55f7724c0e8d94b0b752bbe9f445c78ae4b780781c9bcfc5141b1e46c767a51990af256391fbac9f4302aaab11928a2ed36ea775c0c953d0d5a4d739c37ffef8863cc1b70481410e29cb7ac99a3c4c6d47c322af8de1b39a17da4ea432d62249b6c35f50c8fade0dc96cb8e946a8008db7a72dfe5e4ce4392d4160cf75c46956e66887d82d7e31649075a86c3ecb4a936dc331e78337d5648318")),
    // from wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBKrsc2NXJvIT+4qeZNo7hjLkFJWp\n"
            + "RNAEW1IuunJA+tWH2TFXmKqjpboBd1eHztBeqve04J/IHW0apUboNl1SXQ==\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.ECDSA_P256_SHA256,
        Hex.decode("4d7367"),
        Hex.decode(
            "30450220530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23022100d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9")),
    // from wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEKb23bV+nQb/XAjPLOmbMfUS+s7BmPZKo\n"
            + "E2ZQR4vO+2HvGC4VWlQ0Wl6OXojwZOW8mlJat/dk2tPa4UaMK0GfO2K5upF9XoxP\n"
            + "sexHQEo/x2R0snEwgb6dtMAOBDran8Sj\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.ECDSA_P384_SHA384,
        Hex.decode("4d7367"),
        Hex.decode(
            "3066023100d7143a836608b25599a7f28dec6635494c2992ad1e2bbeecb7ef601a9c01746e710ce0d9c48accb38a79ede5b9638f3402310080f9e165e8c61035bf8aa7b5533960e46dd0e211c904a064edb6de41f797c0eae4e327612ee3f816f4157272bb4fabc9")),
    // from wycheproof/testvectors_v1/ecdsa_secp521r1_sha512_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBKpCL/Ftw4XvfrnQpSZSAi/KkLatZ\n"
            + "r4sFI6Am1kCio9bTRFILYhd+LPoznKQvsIg+xCWQT72igzo7WwqaAIETZdgBIzPV\n"
            + "Mvj46xpiPDeKNpRlEZK72oM+O417j5Cyv8mwRfilXhtqX+FRLEAMS8nIb9fGmdZC\n"
            + "9c7pu4J8iwq8DaAc7x4=\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.ECDSA_P521_SHA512,
        Hex.decode("4d7367"),
        Hex.decode(
            "30818602415adc833cbc1d6141ced457bab2b01b0814054d7a28fa8bb2925d1e7525b7cf7d5c938a17abfb33426dcc05ce8d44db02f53a75ea04017dca51e1fbb14ce3311b1402415f69b2a6de129147a8437b79c72315d35173d88c2d6119085c90dae8ec05c55e067e7dfa4f681035e3dccab099291c0ecf4428332a9cb0736d16e79111ac76d766")),
    // from wycheproof/testvectors_v1/ed25519_test.json
    new PemTestVector(
        "-----BEGIN PUBLIC KEY-----\n"
            + "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
            + "-----END PUBLIC KEY-----\n",
        PemKeyType.ED25519,
        Hex.decode(""),
        Hex.decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
  };

  @Theory
  public void verifyWithPemTestVector_succeeds(
      @FromDataPoints("pemTestVectors") PemTestVector pemTestVector) throws Exception {
    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pemTestVector.pem, pemTestVector.pemKeyType)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);

    PublicKeyVerify verifier =
        handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);

    verifier.verify(pemTestVector.signature, pemTestVector.message);
  }

  @Test
  public void verifyWithMlDsa65TestVector_worksIfPrimitiveCanBeCreated() throws Exception {
    Assume.assumeFalse(Util.isAndroid());

    PemTestVector pemTestVector =
        new PemTestVector(
            ML_DSA_65_PUBLIC_KEY_PEM,
            PemKeyType.ML_DSA_65,
            Hex.decode("aa"),
            Hex.decode(
                "33aa7b0edd5bfb07cb91f07a958bb2e5a458e49182f73b18dfecd8e14d7ddf1882be270e0e53c12e27a822eade61ba265fe8c43b64ebaa7e6023730c5a1258c5a45041ded5fa19cda7f566e474dc549bea12d379303c9e0da024221d57d844db50a3519e90598e49621cb2c5d1a34d1e0ce6b9088c71440472aba7c74cd74fe9759d454c8fa8d69ee67e1ead74dba9ec42c0aa0877ccb1c193b73063f83cd7a084e12ae3d7f216aecac5a2fcfd3e5917676ea2d74514acf2ddaf204de30048c6d8bbcd1ee3d2d1a875af0d7ae5719c2f48ed43564ea8dedf97ad7d4b0450067023a2062c50f6320767ac65ce7f8695cd4edf440dabaf6a5ff570f811944d4652c79c6a3b015a849be7a7962ec708ad59abe63d6e27d5bdd7037ff053bca5d1866af4ce5f6631fe05f72c0420b5d8ffe7d5a7ff0a3e465ee6868f412d5cfcfe7caa62373592cb36d99a32963b5556729ae6083723306141a2baf08e7921ce140bf383ee9a651f5dceb208ec98630cfc96466bc11686aa98b780775b84163600ef3cc95031d50c6c8d48bd89b0dff571367a8a16ea260e0e7f0e00998b0f233c9769a4b10660c185cff19a5142efa10d1e7b94fb300d784568362f964507a35803af6d9eca514f874ef3af3cd3bda51d7ac3acbad086b4474c41f6c782da5847f8c29c59a07020361466852ef15e0fc94dc2851c6410f7d95c96353259c72174c7db04154866a9217b761bd2c39089db216ceeb5cd30bcea197992b005ede0309638731b67d16b5d6c1972a58c0d0590acec03ef3af1dd4df9c5655edfb2f1ca440c1b56dd4172e79aa711eca2225252badbfa657b4106dc941ce67a930046491063e5fda4c63c586969f54a330e6bbb296aee8f3a11dd66a9287ebdf0f9256c504c1e7eb055caf9b5b3464e74c342af41abd6e294105b26cbc5a48f7823e894f58c6806e71ac4fa92e6a7fcaf24181ef4b1031f1e2691685de572503105bed71ef0417d358cd93766ec5d073dbe607033f7001304d5fd45f34bd4ce06772c6d2185b796c42b9d5afd5d4338e7a0ddd5333e1120a44a4c5894bd50a5c8168d69a109712b4db41e27c237621def54ce3c1e5db5fbaac5aac2d1a14f4da4e04f1d98cad84762cce6a2351bf9e97cbf7a77b75275c275b5d781c30f30687a4f1f0aceb8e422d130bce433c7569c222ec98507552e3b5d4ac7f2a2332f6c1de17f2079c80b1d159fcfb33585dce0a5a787bbf2172ef3df7e851c36d9a5fac22c8e39cea72cf28af82a0af75ac5ce633c104d73d34897cb90708a01766890133c5332b73d43130a51e7a502ec277156fa9a1009950c79c7102671fc8b2e7cdd18442f513e3efe36641fe45e5aa8406976066839c1a9449e4235cd22512f3ab43b21320ba06f88628a2162844af532ba27c213bc80032a76fcb04f56c21a67d0f9e9d90417b2de27d645182de645efd32903f7fd5daad4b9c5f5017a6b5965cabbc8d4d32bc6060f8fd88b7ad9917f9a193a99c584bf6c41b80a74b9c05b6f06307bb9fbfe6ecaea7c55d3b891d9103a775f65c1d9b989542ec95b516995e8e7712a3be683a7a198a100f76d54d3c7d8c1b602f496773b33b135b9978fcbdb0b661f5cc1919757146965c1f0a8191060d824970c4fc634718b1b97603a5374eb47ab6f1a85354d39197ef69b4c1b59fac350636e0ad0fd6fc03fc6df3f9a65f1bf948e31070527cf8fd09cbc302d3c5bfbd6fce5b84742fd360c49015d8d0002b8c2cde87babde946cc0b2362983613a07ca6fb494df591c42d6af6c8abce1161d3acd6975c9b33b1026f347c41f0ef5b7fdf0168317d948720f9dbb609c90cd05f2bcaa7cc9d4ba73e6ee975d9b5b6e2d034c81a6a8fc0605fc0142f090035b5b6eac543328d50c6e6b8f3144748905feda5ff5d6f24b1124e534387e2d70639d0afe81a7a6121b5df0d03c778a87fd04eca9e5fb5b7c7c2189794b9c4ddace4548f805cf379a2683762a626d20d9881f81a149c32956223d4bcc336d7bad6be9ebcaaa956a8ad53020ea4ae942cf9660333f72ce05f5003363561a2bbc2c4bd22f257e41414de3369be78f91c64c35abaacfbb1eade5fbe955c7d5cc8c6ddbd4754dc9f3dba8062b907b30e8d07418d29e65e1bf97d8919e85618fdda5be3910e969339e901d9d8b175f3a7560cbdd1f11eb571cb0ccbd323628c4d5dc5e44f88f4eff1ac793bfcdc7b399931c985d91aead7cf3c42ccd3e3ee246303f3086ef213d0b852c6af2e558f9818f6b799dd13d593f441bfeb17a34d4aada95721a04b475fa54aa43bc4f1dd6a026404e0722d9c2bb955e422e41e067ce009c53f832dd1668e431c407ed467a78409e26f3ca0ce62ee7a1485702886a9d8a6cbd5b4f7863bead2b62226523d05c186207889485063422ee441680d2cad7d135592adb194b2a0ede0f6753b2986872681652e5ad5c5926f80fcce5ce120086c932940c3269fc5bd83d2a9f811645722de6270f3384b3c1acd138b0e93f25ec0120c4dfee4ae5fc077372c16150b180bdc68afb489aecca0ca14e794ff3049a3fe577d10dd380e219ac546989e2afd1e0fbb32334a6da24fdd01980937efc42c5aafc2689e8c57cae9f325f17fa099fe9c2f4321a1edde626a2855d70d18424d3ea9f643f88203523a15e375d1c6eb8f1904819e852e5955166da915462e615e8a2b1e5913c26b874e523cbedf2bfbad21ef3c3477becd3abcc840eed25484e4fd2bfb8148a767638a3c268475eadb8ef4c9e83709445eabdfebbddffbfe2b48fc00b85a6c532c7a44b751637a3dd7a0e8095226f66a02f66d9a3b5059c0d7181ecbc8f672602a5e88a211eb0c55a4076176a9fa644ef5e70f526a2a2b72703eaf69a4809c5c858a412a00cc060e4dd7c175f1740548eaa468d0275dc5f1ad2e6bc144535dd2e755869148774d9d38db1d68546d303edc2c7b9b0c0ba978b2eda079351fae76d34075c9b31a62a63b5068f040d35b45bc21a821be784aee06bbc719f9d18695a477d501e2a8cf127936fbbb0b2ed5dd8741f57f18aafd42b45fceac85746c0bedbb8bc590e2cc88f3cab9ff8a4d9c0a89b908e8232192fb6eb8a5b4ba177143156047e40651e687298ed786a639b630b1bdc3c25df9474a8bf5abfe0574eb9e472b004ecf934ae2a3a7c123200e2bf743b86e70d930c825cd052e0bee11d03555c976ce8a58fb06550721dde6be4eb52d5f0b2dfb76a4bebe87131d4f7b5c012d8be39f010d24f5b6ef7dcae59649b033c01fc6a0773d8c9f3ca6b547633e38dba01a5a5c8d7a9a273b6578903603f12ce066c774f72b5f1a67b2a8598ab2c89c8c14234a1f46023be69d70974358d5b7cc378c480da83253e669a30f7dc545b3c45f71ce7a0e3a3ea836e72d7eb6dc3ecc28885eccd966fe8e5f9d66c46a71aedeebe7bbdf863c73fda7c546a59b928a5a4605da896fac2238365c1a5b8550b7caa341493d0536e6704c2bf0e3977ad7d5c1ac9ad3bd8a81267cdcd2199fbf54e7d3587d86f69a278ab4706d18bcd6ab5c2ccc51fadfc09888df0accd2680dcd6161038a6e26ba10c9168b2f7e30ed844d0f9b9abc8e06415f36a4a59e89218692cae421159cf34e73a127abf5a77a9ac65746c77b4ef470360f9218b8983a0254fab4691fbdf176dfe550e19c935a831aa1e1e6dd58bebd0fae32db66b365ef32d69eac206f29c63de02fc76b9f1a156cc0b614960d818b24e4c429b2563a567a437c3d3941b6468aa4fa99307312ae7c18c4e064d57a11b0ae1836798f489b42dac9bbc3840e0b55b4c7c69871d9f7f53502586d891c4ab7c306bd63cd596988bb68f93fbbe9bcd0f70d7f78ae67b738b69713dd82a3f542714117846771eb7241801c27d2ced049cdd2237941ea4778131db8d1b106cec3faac39e986f6bb3f14f08aec6afc9764f92df23bc0c1c2c579508b2e429c7104fd7fa871b57c5c1c1e4843a6d90a0056f00bb2c76dc3f1926212d11cebba523c3b2cbbc85a60f617cae53259483d6b7feecd3be5b6b14181d7302a215f58667ebe7ec16d375d91a2a3eb1db981b1a7a6f9c2e6647db6e1e06f27ef2428fc23715eb6de9e8d9e6f71a0a4631f9c51ffa3895988d851d1a90a9ce9d1766564b3acefbc08ed66b632455335ac4684b683cf22d1d91245f4077911fb1d6a53ed32e1d30e8c7a9d78b3dbcf742460b36115f5d8c7c75e14c7063045a2fc0f5da89b86c8af6ffd2c5761f50aa8a1b528d33a8cfd69854b345e1e4891b39b52557a32189c8327fb0c6cc108b070705dade504650b60f4486f8ebdf6cee46180ded982efbc3b7ca70cb0d3c131758cb98bdc1cb8a20f1107febcab51c5e281da87cb92d1b277b1fb7c5ef1db4d646f865c25c9e0ae6c33371d2520871cec9d089affd8e8f33ea2ec4030af6cf2b359d883171430f700f1f4faa6e1dc70c65cb00f5a1147d0efbc14fea4d21685b5ac0f2d0004142ad746835159101b532b5038df05c0af8f334e11f722054e5da3fa98b00aa454dabea63b726080fdb383770dfa3903bc4f4f72957e378322f9f058e9116a7a172ed0f33ae155a12375bbfebf2021e7daa8e091a334172ff6a768028457bd6dbe2f200000000000000000000000000000000000000000000000000000000060a0b11141b"));

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pemTestVector.pem, pemTestVector.pemKeyType)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);

    PublicKeyVerify verifier;
    try {
      verifier = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    } catch (GeneralSecurityException e) {
      // Ignore.
      // Older versions of Conscrypt don't support ML-DSA. We only test
      // that verification is successful if we can create the primitive.
      return;
    }
    verifier.verify(pemTestVector.signature, pemTestVector.message);
  }

  @Test
  public void verifyWithMlDsa87TestVector_worksIfPrimitiveCanBeCreated() throws Exception {
    Assume.assumeFalse(Util.isAndroid());

    PemTestVector pemTestVector =
        new PemTestVector(
            ML_DSA_87_PUBLIC_KEY_PEM,
            PemKeyType.ML_DSA_87,
            Hex.decode("aa"),
            Hex.decode(
                "c562ac64ff138e4ead4a35766d750d0f8b2dace6b179a09956940ac5e8455e6e12da1f4b2f213c37fcfe40b5cfe762ac118fbd1e083d6e2aa575d37fdd16ed9ed0c9d2d1baa738dc580834595cd0ec83e2b698771275f79ace6ff5b0a3e394666825fbcc425f7531b5de51845f6cb45e084b9e9d33d558a1d02ad23bae2550f512048d9de1cc2b5e06462e9187ee1dd1e1457279910bde50dec5222f5b183f2fbbdca4ddbb3d0edb2ee5ad061e5d40d38fa971b0825a72bf7dc51d1efcc364b9eefd0735c215fba1b5f2acd26b318f18a6aab74ce20907b8ec917bca6da540e7f672c04e36ef55e35a06912f178726f2341bfa3410cae54b50177f6730e8270b035a8b90196d855000a3b8c594b7f24e23ba2b95892682aa9e11b9b57ab8468658ac9d93251e46630ed8de0113ce46f9a196f08bb5f71c10693bcbcb07d36f92bd56fb4128a75fa2af9546f4d8918446457a49b2d3105ba5c7328bcd632eb2b6b50836bc8ba1b75af9127b7bf9ae0d6ec01c8f5cdaadf700e3fe78da2e815c431f53f88bc25b25463787902d24b3146fd97522f7a6d8f7fa3bd03161f98055f70b727db8ccaa7969a0f360984926995c44124a58f5d6e1bd05a4658e20905ddae1de5b4437d16da177264875a5a12d944d34a1863b391cf97c487a1f001989bc2bedd1cf15741b7539d8f0376b3968b3f702df2da1f170e59de8c3c5dbcb11d191bc9b01cfdc1a013bd300c6bb78bd2c98eed33ad934d1e90fcd613b11b1c19a105117ef2df98aded2bf238d4b28a5789508c1cee13ddb6d03bc536957ba2a3f3a639e322d2c8dae814c725d06d630ae5495e06826a97c8b556bba389e09e1d877d6f16e6711c2f2fdcf24281a422396540bb6392b186933e18bd90f16b8eab26f15f551d27c7672c3be09110b8e61bd9d2e6ee496d7c12edd5e06b8ae3b056d08eb47677d45f10003b10a220af906b42215f8872a4fc3a9451d2cd9d6276297ea29b23a60ce919e8d9b335ef81a045691f9e44256251051620074eb0202cc4891159991c7a0f30d86ebe5c531115e54f4e794f75f854d9c84a95edfe4e5592a4bb844cf78a024faee6007800cbf139b997c820ee03aabc212a624ad8005245b52d10e21ac204daa7b3ab13d864f4d0fa53fb69965a475e7efa32c821e7492b8d4551b7ad3b2fe29d252a5431d823b4a26f17f02a76dc2af3935d921c6854ce4072aa8cebf658f34f0462f7b8e8fdf1280e4bf6fa7282ac9e0b923ea466315455555a2fcbcfa53872500c73f5807ce2598c25ee5875a45afbd6c86595e189b7e8f535597bbb139752806a6c99c1054dfe39aeff60afd3071541904dbd57a3547b55eb22d2e25be049358977abf5c4c1a1af8832bd1bf52b18a0f2a07e5914acafd4b675716ddad1cd043db8a7f3a2325d66f2d95d44074f4e0fc8eda5689d1bd85fe803ae5fae0512d2d757f63a1b8d25d5f99c5dcc5ca558d49a42c9081885b9ea3b79eb01b6c17c1d466cef13d6d9286ebe1396994c763fa65f365ac1267e516361ae39ca69a891079412391cbea740d9c6b7499155f61222944c1f098bc5825e4c329b6b7bd23ab7521ad88769df403f150bc9108471879ba25b2117b691a4720280e57150185ab6913be0aaf42d882a97ea015e945b6ee29d5f6b4ee4c09e5059b51b2fbdd2173b681f01fe4bc1ff6946e7d4c22f2e207788c6183a4649a16ebf7d6bec8220523c96f22f75c193391c13fc5da1ddff9ac4f29d9f0f1a1e27fdd2ec8bf052cc448bfc39381fdc0bed332fc8ab9e1209fe26c315ac7a11680d3b06aa1197a60eb1f732643af2d542830076810f066b3b8a683593eb9eee9ee6917274954ac5492b9799451b7f61d8b7fcc73cecbac6866ae9abf0100360e71bcba603fc12c930844f79d4e4445833a0fb85feec7891eb382ef92394e6436ceb6498733b05fc3b414acae0a25e79a50f8e182a1150fe78f8340f0fcd2703b1c5c28833b996a747c4986703b34e1f88c3b5de18f9cdf072350d7abeebee4ea965062798d9bba409bb634389b7fe8a947101753b649f52df3d711053a9c315d3ef7e211ca293d6ce34992a3da46a05a565ff7ca82d1e731ec45bedf7e36e6564d7a6281ab1fbdedbfa0449f60b77f6ef4c5225117a0a8e270a59999d2866e44740c3fe7910c29abaa894e3ff5960052501d70571b2c7d479b6a06c6e19524ba7570236ee81f3fc90e2cfa8d17c68461bf4ca4b94f6ea7df5ff40961c0f4875cc92e8f694b724adae1232e7c7ac4dc32a24f18cebb9cbfe672de4136ab33420eeeca9370a9361b9e16f7c62c1a1072e7cc5a2cb8b7d3b6a74ba014b57cb6e65dfe6daeb7ad2dc2e6b2ce993b8bfc0a616c03b103a4ee70ec9af982349cfcbf9c8636218db0929895058e9dbce260b5b88d68e2f3240e27fce2d1192027458311732f822413729dc3e97c553cd3781dad4cf0f528cd933aee21e6b48aa776155ecfd3af3e7e0b78781bc75e50f452c7c2656edbe39d0129623c8eae62715ad3e99aa482fc0fdb52f4e1b95f1a0dbe59617a602abd03f7bfcd44dabbbcb46763d94801227fe67207d461333d71861e62801433e13d26be1b712b3a9cab71b7dda61739b6ef2cd9799febd77c3b90174276e4ba6204b2721a6d90d3bcb62874ba0d78f4f29bce4599c919d68d4cc36b76830ddbc5e4ecef115b0cc3bdb46535920a7a38d64020968aa0ff879f30ca564e8aaa403e4e3f090991871c550b3a467b33e790e3615c159145abca01e7a7dacf03bb48ecfcb6d5c130efdc63f20c3072e6730b5d937cb880565487e85fdaa56f6a9f2b34afee7c40c98c91892b3b6d37ce4a290b08f3bf2cc52497262eb400a149a282f6846e3d7bf245714a5b6e4653cc6cf7b6402b29814dfe9d88c3c2252d2c8ac9a08ea50937ab8b0495d2cfabd45bce17a8b7c4d518d4bbb73fe02fd0989d65bb997ab074a6e791156512ae34b45b27c05134b2e0101ae8497764ac14b463b6cb98521e56f3fa3f4b4b71a402d78a38ee6abf21c05b6b4897fec15b2ed72335397ba7573bd937c741e2f148d1134f1844132d2449994964dba5dcc87ca2dd5594fdfee9f6fb4ca31c63f3a7b1e8124e358a19f45b4ebe3a86765c4a301a626ef43fb986b66bee47c12a5b65799b96bd1a7373cc4ef4fd1e585243400dfc13a9c9167de69cd2d002f107cc44176da2d00acd9bb676a004588c6dc25ac9d0df54d2aa9f88f0ea5a50b0fda8db847436e866e9e229e72e4abe70cc77711bb5928a742edaa444217ef69f54d3ef8ea1a0e4ec72af624c37cc9883b5d3c1e75f81d0df9e3e3b815c5e38099529b6a9f0109b206a8aaaa97f702273198c5efb30dbc4eb4fe5b06088bc342aa608e1d0a490e9c11fc60cec34026df760a09fa443f05f7dbdc52d69fa269832b50f1f4d8df9f13186c58c91a48a53dbeabc127ded3daac7c7555e358901cb81d45ffadeb8610f62bf29a846a3f9ebe9bb32a986ca492b91daa6cfccd65af25f37059d7187dd48e971360d592662714af9aacd8f14ac32329e5e13346c3c6ce782fd51266d70eee118c84f5a6415fbd5d3fb09bc0da351f9599446d5702218a702b50580d86baeb441d501f0ab6b5cdbe222617e538fbd0e65fd07314d01f9ff66c6c42a9bb2d8b62f82e24538f3d1cb78e5100d0eaf6eb5cbcadafe38dcaa7569b067bc04fb1f854ec9fef830ee89a187e6acf672b95e9a088606058e4ddd87f2123183f539b750eb3f389c83674a8f553508a5db05c85c5957511616742de5ad772b5922ee3b5f90a21d4b872f529b1d6ad20283be17b6cc406870ff4220d0c0dd2ff78ea696eea7436c4c6ada62bb697f0d58bee13246c8dd7270859bb3d5ea381b860120d9cf85ded4374192f81bae9b353ffdef44451c39e439b2d47897d3df874b2e0778335095a395061555229dabb8458c8d2368032121a5878a68979eedf000f88dcc08d041aab8e68f9ef9992dcb974e5ba6561bc3275da161750bb43f5fef92993803a6146a3f82f91eb4ef23c4570f5e1c69f372736700809f4215fc1b81c5c64ee57432b9f944e0f4bc84eb3e93e5801ef86a457d94a90d510bb1b3b15e400503fc1243998f0146e404fdd3488c1c880192ff52442cf2edda388d22625dd97fd38088b63cae7c6d180adb840879a268e5c8c5c2fdfa41a39ff7ec5aee2d7b47c66a82c9c20e26b8837053455faa2411e94e679f0f944caf165646bd71c21642a2949719efa1e0125d08be3c995f12caed74b2cbd9d198e487a3de179b8ad89751996f6ab6f1db56cf61d1af366c19e996b26fd2f7ca45d5204fce938683f15bbcbf9f27afccc9ad796d0258757ba4be8d27ac74c20963b91bc78a26c555441898b5c9d522dc1b47ef9418dac4b2d7fc438b7f0830a616375b9e33a29e34728c192a35679855453c1e68b956f0498ae3a41e03be286d47198bb9b0519fd0bd728a70da8691aa132f57e92c34f479dd95936e63d98c3dc427eb5ec8e64f9f892612fc1ebc0e97ccb86465d8e405d510ee3c6c1b82d2176d6a59a7fb59f428f0d81ae423d62af17b062c0d50c5b83c4d385c77447f082ed8be7e6ff6e8b9cdc4c5c4e27a8d5a57ad5d59e147e6e84e02a6792528695e0c01a3edb7643faad8297a563c2d6c00348f8b4db6c9c3ed40b5be1e20377c9f5fd92187e7efa4985b0855dee923797e5350682949dcc243b2c4d35be0f3bf7dcee82cc3656abc4302935b47736ce6585c17f5b4aa4e9b227b86d6d016f60ce84d6f3d51f6997e2c771816a37bf1211fcf9bc9b2f07ce694d3e4e2d672d0617f502e0a932d21ba5b5d45c720f4f5b94ca89fd6c4e3c85c865fb6cee683dbc52938636bb0c64503ea10faf71f63476664a2f84e0991e94747ac542b503a6940f25e6b277978d78ca447420712f83ab1a26a5b9857d3d3f0823163f1c4b8643796fa7981d0106aef063aad74cc59c22dbe98996a88db18b620674bfb9300c8316dc8a477ace7cd669e10a0cc0ebffc6d4915b89af87e7f989faadeb87840108e5962983d93e11e5afdf3c18785887f89520654094e4cc58d45cb3b1bc7d18e1138fe8314cc3969dc9a1842df1da4ad45cb5860bedc6a1b169b77fd95a379ce60a39e1975dbb635642ce2f4d17067c91caa727b4aed7c76496d65775a265499b29ceacf178c695800601a54db27e373178464e15019dc9fb9a3bc387c0d3165876d37ffcf4d7c01a2ae0ce8426d8562491ad6dba52f120bac753bce81b2b86d7af5196fecfec9de97f269d5c96026dd1fa53e1cae485ae05c126ac816a3201a13e5dfb80625204d7a7bfb1515eaf2ae707038f3274a9eb9c80d3f315e9d3413d6ad94e106d47b3aeb9daf48480f979ec5eb0bb566f60bdf5c5e4d4852b92c96a8ab6150824d6414da2428dc5a0908405c962b027014f10ee72b1043d6a3d1e34e152b7c71b64261c2c9f45ee96fdcb4e2220fd8e4bdf03d4046064700eb590d1126eb90c0b59583c464a473d88427ac80f1621c3097d6a12eef87dccab6fd0a06fd96d81b0f792e107334e15645e9f233e41caae8dcc21fbc371601f765a519d10aef6fd471fa3563124a94fb0a6b0c57b3d19993e0e71ebd0c309b5afb9f15e69ac367843ce0709c76d4e86426a70516aa81ddcb36077cc824bc930a1311aff513a555cb1ae0b20b86a3929b9976d99ec4d44669d6bbfb9b015d43eb920a58e060e90c16a7abb0938057e62eecbe56a29af3d4245967d764968c2a7feb63a3d9a2345105a37dc46f46fc1ebe9b1046360aeab94b9e410319bf5d7a5f3ae41e34e1363c601174886e5c6dbc82fc7480e1ec6606eab4eef9b63e1d8455bbe39127044a763bc66ecd8de2a643f80394c842c81738cb6729f26702797aaa1a12c55295056daa52268032b43fb9911f7615d93b19ff5ea3633c2067ead713eb99a242e84668314b3cfd1bb3d57a44935bdda472d08a1c792e7be8aa51d9c2d60fd0197b5f078787a05b49732131f73f40c76baf47595dc77de694a4b5dc8ebdf500f5459735becdc89a65717e6a1ac6e212ea74cc5e93787ce43cf4a459a80527efc9b56463b625fd454bc450fa2099e4d9bf42712b0e719ecda7351371a236d7e9f513871e7da159692666c25dce71c58f60b3d5a764d3588cca1b00b0c8336b3ad72866bdafdc26ee6a89a0e5a01a7bc3a5048e14e532fe3085abaaa413e85dc3c0042fe88e319fff8a1af5d77aca76b2758e2451221a98c449da1fe6be94da599cc2a8ab78615bb34296f9c1391bf9175eb73b26a9a0c266d89b05e0af04e7ded55b84f72c9f2236df08938fae495c31d81d7151df6f181ea90e15c81f28f5f97998094d67056a24bf62ea9a96dee2a3df523d2639df81c7af65a716299232ba8d8c4ceb9b250ee5c823ddbd67bf7105101e59040696a7a9c8466681a2a5d1f73a4d6277a8dcecf8304c4e6a6d788ba2a5fa2a628bb0c6c7dd4f60698f999fa30000000000000000000000000000000000000000000000000001050b121a242b32"));

    KeysetHandle handle =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pemTestVector.pem, pemTestVector.pemKeyType)
            .buildPublicKeysetHandle();
    assertThat(handle.size()).isEqualTo(1);

    PublicKeyVerify verifier;
    try {
      verifier = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    } catch (GeneralSecurityException e) {
      // Ignore.
      // Older versions of Conscrypt don't support ML-DSA. We only test
      // that verification is successful if we can create the primitive.
      return;
    }
    verifier.verify(pemTestVector.signature, pemTestVector.message);
  }
}
