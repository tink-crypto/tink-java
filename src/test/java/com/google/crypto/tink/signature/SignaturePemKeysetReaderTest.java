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
            "3066023100d7143a836608b25599a7f28dec6635494c2992ad1e2bbeecb7ef601a9c01746e710ce0d9c48accb38a79ede5b9638f3402310080f9e165e8c61035bf8aa7b5533960e46dd0e211c904a064edb6de41f797c0eae4e327612ee3f816f4157272bb4fabc9"))
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
