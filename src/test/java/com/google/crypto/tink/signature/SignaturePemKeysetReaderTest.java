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
import com.google.crypto.tink.internal.Util;
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
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
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

  byte[] addZeroPrefix(byte[] data) throws GeneralSecurityException {
    return Bytes.concat(new byte[] {0x00}, data);
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedModulusBase64)));
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedXBase64)));
    assertThat(publicKeyProto.getY().toByteArray())
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedYBase64)));
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
        .isEqualTo(
            Hex.decode("00D4CE489428982EF343186EB90E6A04ADF41366359A508FE7AC66B283F06641AE"));
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedModulusKey1Base64)));
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedModulusKey1Base64)));
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedModulusBase64)));
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
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedXBase64)));
    assertThat(ecPublicKeyProto.getY().toByteArray())
        .isEqualTo(addZeroPrefix(Base64.urlSafeDecode(expectedYBase64)));
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

    KeysetHandle handle = LegacyKeysetSerialization.parseKeysetWithoutSecret(SignaturePemKeysetReader.newBuilder()
            .addPem(ML_DSA_65_PUBLIC_KEY_PEM, PemKeyType.ML_DSA_65)
            .build());
    assertThat(handle.size()).isEqualTo(1);
    MlDsaPublicKey publicKey = (MlDsaPublicKey) handle.getAt(0).getKey();
    assertThat(publicKey.getParameters()).isEqualTo(
      MlDsaParameters.create(
          MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX));
    assertThat(publicKey.getSerializedPublicKey().toByteArray()).isEqualTo(expectedKeyBytes);
  }

  @Test
  public void read_invalidMlDsa65PublicKey_isIgnored() throws Exception {
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

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(invalid1, PemKeyType.ML_DSA_65) // is ignored
            .addPem(invalid2, PemKeyType.ML_DSA_65) // is ignored
            .addPem(ML_DSA_65_PUBLIC_KEY_PEM, PemKeyType.ML_DSA_65)
            .build();
    Keyset ks = keysetReader.read();
    assertThat(ks.getKeyCount()).isEqualTo(1);
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

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(pemTestVector.pem, pemTestVector.pemKeyType)
            .build();
    KeysetHandle handle = LegacyKeysetSerialization.parseKeysetWithoutSecret(keysetReader);
    assertThat(handle.size()).isEqualTo(1);

    // Older versions of Conscrypt don't support ML-DSA. We only test
    // that verification is successful if we can create the primitive.
    try {
      PublicKeyVerify verifier =
        handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
      verifier.verify(pemTestVector.signature, pemTestVector.message);
    } catch (GeneralSecurityException e) {
      // ignore
    }
  }

    // Created using Conscrypt with the private key
    // Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")


}
