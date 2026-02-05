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
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.IOException;
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

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
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
    String expectedModulusBase64 =
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(RsaSsaPssVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedModulusBase64));
    assertThat(publicKeyProto.getE().toByteArray()).isEqualTo(Hex.decode("010001"));
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

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    EcdsaPublicKey publicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(EcdsaVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(publicKeyProto.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.DER);
    assertThat(publicKeyProto.getX().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedXBase64));
    assertThat(publicKeyProto.getY().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedYBase64));
  }

  @Test
  public void read_ensureUnsignedIntRepresentation() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1M5IlCiYLvNDGG65DmoErfQTZjWa\n"
            + "UI/nrGayg/BmQa4f9db4zQRCc5IwErn3JtlLDAxQ8fXUoy99klswBEMZ/A==\n"
            + "-----END PUBLIC KEY-----";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256).build();

    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    EcdsaPublicKey publicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(publicKeyProto.getX().toByteArray())
        .isEqualTo(Hex.decode("D4CE489428982EF343186EB90E6A04ADF41366359A508FE7AC66B283F06641AE"));
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

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsa2048Pem, PemKeyType.RSA_SIGN_PKCS1_2048_SHA256)
            .addPem(rsa2048Pem, PemKeyType.RSA_SIGN_PKCS1_3072_SHA256)  // is ignored.
            .build();
    Keyset ks = keysetReader.read();
    assertThat(ks.getKeyCount()).isEqualTo(1);
  }


@Test
  public void ecWrongCurve_shouldIgnore() throws Exception {
    String p256Pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(p256Pem, PemKeyType.ECDSA_P256_SHA256)
            .addPem(p256Pem, PemKeyType.ECDSA_P384_SHA384)  // is ignored.
            .build();
    Keyset ks = keysetReader.read();
    assertThat(ks.getKeyCount()).isEqualTo(1);
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
    String expectedModulusKey1Base64 =
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key firstKey = ks.getKey(0);
    Keyset.Key secondKey = ks.getKey(1);
    assertThat(ks.getKeyCount()).isEqualTo(2);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(firstKey.getKeyId());

    KeyData keyData = firstKey.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(firstKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(firstKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(RsaSsaPssVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedModulusKey1Base64));
    assertThat(publicKeyProto.getE().toByteArray()).isEqualTo(Hex.decode("010001"));

    keyData = secondKey.getKeyData();
    publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(secondKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(secondKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(RsaSsaPssVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
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
    String expectedModulusKey1Base64 =
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    // The EC public key is ignored because it has the wrong type. It is not a RSA_PSS_2048_SHA256
    // key.
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(RsaSsaPssVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedModulusKey1Base64));
    assertThat(publicKeyProto.getE().toByteArray()).isEqualTo(Hex.decode("010001"));
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
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .build();

    // Extracted after converting the PEM to JWK.
    String expectedModulusBase64 =
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ";
    String expectedXBase64 = "7BiT5K5pivl4Qfrt9hRhRREMUzj_8suEJ7GlMxZfvdc";
    String expectedYBase64 = "KW4vxoWD7iYvBp9h9TWjCWXC2aOTCzysshk-bt7tVQU";


    Keyset ks = keysetReader.read();
    assertThat(ks.getKeyCount()).isEqualTo(2);

    Keyset.Key firstKey = ks.getKey(0);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(firstKey.getKeyId());
    KeyData keyData = firstKey.getKeyData();
    RsaSsaPssPublicKey rsaPublicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(firstKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(firstKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(RsaSsaPssVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(rsaPublicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(rsaPublicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(rsaPublicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(rsaPublicKeyProto.getN().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedModulusBase64));
    assertThat(rsaPublicKeyProto.getE().toByteArray()).isEqualTo(Hex.decode("010001"));

    Keyset.Key secondKey = ks.getKey(1);
    keyData = secondKey.getKeyData();
    EcdsaPublicKey ecPublicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(secondKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(secondKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(EcdsaVerifyKeyManager.getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(ecPublicKeyProto.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(ecPublicKeyProto.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(ecPublicKeyProto.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.DER);
    assertThat(ecPublicKeyProto.getX().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedXBase64));
    assertThat(ecPublicKeyProto.getY().toByteArray())
        .isEqualTo(Base64.urlSafeDecode(expectedYBase64));
  }

  @Test
  public void withLegacyKeysetReader_shouldWork() throws Exception {
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
    String expectedModulusBase64 =
        "v90Xf_NN1lRGBofJQzJflHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS_6akFBg6ECEHGM2EZ4WFLCdr5byUqGC"
        + "f4mY4WuOn-AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S_7FkKJ70TGYWj9aTOYWsCcaojbjGDY_JEX"
        + "z3BSRIngcgOvXBmV1JokcJ_LsrJD263WE9iUknZDhBK7y4ChjHNqL8yJcw_D8xLNiJtIyuxiZ00p_lOVUInr"
        + "8C_a2C1UGCgEGuXZAEGAdONVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv-TYi4p-OVTYQ-FMbkgoWBm5"
        + "bqwQ";
    String expectedXBase64 = "7BiT5K5pivl4Qfrt9hRhRREMUzj_8suEJ7GlMxZfvdc";
    String expectedYBase64 = "KW4vxoWD7iYvBp9h9TWjCWXC2aOTCzysshk-bt7tVQU";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPem, PemKeyType.RSA_SIGN_PKCS1_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .build();
    KeysetHandle handle = LegacyKeysetSerialization.parseKeysetWithoutSecret(keysetReader);

    assertThat(handle.size()).isEqualTo(3);
    com.google.crypto.tink.signature.RsaSsaPssPublicKey rsaPssKey =
        (com.google.crypto.tink.signature.RsaSsaPssPublicKey) handle.getAt(0).getKey();
    assertThat(rsaPssKey.getParameters()).isEqualTo(RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build());
    assertThat(BigIntegerEncoding.toUnsignedBigEndianBytes(rsaPssKey.getModulus()))
        .isEqualTo(Base64.urlSafeDecode(expectedModulusBase64));

    RsaSsaPkcs1PublicKey rsaPkcs1Key =
        (RsaSsaPkcs1PublicKey) handle.getAt(1).getKey();
    assertThat(rsaPkcs1Key.getParameters()).isEqualTo(RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build());
    assertThat(BigIntegerEncoding.toUnsignedBigEndianBytes(rsaPkcs1Key.getModulus()))
        .isEqualTo(Base64.urlSafeDecode(expectedModulusBase64));

    com.google.crypto.tink.signature.EcdsaPublicKey ecdsaKey =
        (com.google.crypto.tink.signature.EcdsaPublicKey) handle.getAt(2).getKey();

    assertThat(ecdsaKey.getParameters()).isEqualTo(EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build());
    assertThat(BigIntegerEncoding.toUnsignedBigEndianBytes(ecdsaKey.getPublicPoint().getAffineX()))
        .isEqualTo(Base64.urlSafeDecode(expectedXBase64));
    assertThat(BigIntegerEncoding.toUnsignedBigEndianBytes(ecdsaKey.getPublicPoint().getAffineY()))
        .isEqualTo(Base64.urlSafeDecode(expectedYBase64));
  }

  @Test
  public void emptyReader_readThrowsIOException() throws Exception {
    KeysetReader keysetReader = SignaturePemKeysetReader.newBuilder().build();
    assertThrows(IOException.class, keysetReader::read);
  }

  @Test
  public void readTwice_works() throws Exception {
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
  public void buildTwice_worksButOnlyOneReaderCanRead() throws Exception {
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
  public void addAfterBuild_doesNotAffectExistingReader() throws Exception {
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
  public void readerWithInvalidKeys_invalidKeysAreIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem("invalid", PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem("invalid2", PemKeyType.ECDSA_P256_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
  }

  @Test
  public void readerWithRsaPrivateKey_privateKeyIsIgnored() throws Exception {
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
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPublicKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPrivateKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void readerWithEcPrivateKey_privateKeyIsIgnored() throws Exception {
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

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPrivateKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
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
            "30818602415adc833cbc1d6141ced457bab2b01b0814054d7a28fa8bb2925d1e7525b7cf7d5c938a17abfb33426dcc05ce8d44db02f53a75ea04017dca51e1fbb14ce3311b1402415f69b2a6de129147a8437b79c72315d35173d88c2d6119085c90dae8ec05c55e067e7dfa4f681035e3dccab099291c0ecf4428332a9cb0736d16e79111ac76d766"))
  };

  @Theory
  public void verifyWithPemTestVector_succeeds(
      @FromDataPoints("pemTestVectors") PemTestVector pemTestVector) throws Exception {
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pemTestVector.pem, pemTestVector.pemKeyType)
            .build();
    KeysetHandle handle = LegacyKeysetSerialization.parseKeysetWithoutSecret(keysetReader);
    assertThat(handle.size()).isEqualTo(1);

    PublicKeyVerify verifier =
        handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);

    verifier.verify(pemTestVector.signature, pemTestVector.message);
  }
}
