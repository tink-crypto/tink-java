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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CompositeMlDsaPublicKeyTest {

  private static final int MLDSA44_PUBLIC_KEY_BYTES = 1312;
  private static final Bytes FAKE_MLDSA44_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA44_PUBLIC_KEY_BYTES)));

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;
  private static final Bytes FAKE_MLDSA65_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA65_PUBLIC_KEY_BYTES)));

  private static final int MLDSA87_PUBLIC_KEY_BYTES = 2592;
  private static final Bytes FAKE_MLDSA87_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA87_PUBLIC_KEY_BYTES)));

  private static final Bytes FAKE_ED25519_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("02".repeat(32)));

  // Test value from
  // third_party/tink/java_src/src/test/java/com/google/crypto/tink/signature/EcdsaPublicKeyTest.java
  private static final ECPoint P256_POINT =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));

  private static final ECPoint P384_POINT =
      new ECPoint(
          new BigInteger(
              "009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c"
                  + "732aa49bc4a38f467edb8424",
              16),
          new BigInteger(
              "0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a"
                  + "0b2c990ae92b62d6c75180ba",
              16));

  // Test vector from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pss_2048_sha256_mgf1_32_test.json
  static final BigInteger RSA2048_PSS_MODULUS =
      new BigInteger(
          "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d8"
              + "0325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c"
              + "15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed812996"
              + "15d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d34"
              + "95d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460"
              + "d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9c"
              + "f7820283f742b9d5",
          16);
  // Test vector from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
  static final BigInteger RSA2048_PKCS1_MODULUS =
      new BigInteger(
          "00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c1"
              + "24b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0c"
              + "fd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3"
              + "c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4c"
              + "e7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6a"
              + "a09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400a"
              + "a12af38e43cad84d",
          16);
  static final BigInteger EXPONENT = BigInteger.valueOf(65537);

  @Test
  public void buildNoPrefixMlDsa44Ed25519AndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA44_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(ed25519PublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkMlDsa44Rsa2048PssAndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.RSA2048_PSS)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA44_PUBLIC_KEY_BYTES)
            .build();
    RsaSsaPssPublicKey rsaPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .setSaltLengthBytes(32)
                    .build())
            .setModulus(RSA2048_PSS_MODULUS)
            .build();

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(rsaPublicKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(rsaPublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildTinkMlDsa44Rsa2048Pkcs1AndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.RSA2048_PKCS1)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA44_PUBLIC_KEY_BYTES)
            .build();
    RsaSsaPkcs1PublicKey rsaPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(RSA2048_PKCS1_MODULUS)
            .build();

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(rsaPublicKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(rsaPublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildTinkMlDsa44EcdsaP256AndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P256)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA44_PUBLIC_KEY_BYTES)
            .build();
    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey ecdsaPublicKey =
        EcdsaPublicKey.builder().setParameters(ecdsaParameters).setPublicPoint(P256_POINT).build();

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ecdsaPublicKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(ecdsaPublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildNoPrefixMlDsa65Ed25519AndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(ed25519PublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkMlDsa87EcdsaP384AndGetProperties() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P384)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA87_PUBLIC_KEY_BYTES)
            .build();
    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey ecdsaPublicKey =
        EcdsaPublicKey.builder().setParameters(ecdsaParameters).setPublicPoint(P384_POINT).build();

    CompositeMlDsaPublicKey key =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ecdsaPublicKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPublicKey()).isEqualTo(mlDsaPublicKey);
    assertThat(key.getClassicalPublicKey()).isEqualTo(ecdsaPublicKey);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> CompositeMlDsaPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ed25519PublicKey)
                .build());
  }

  @Test
  public void buildWithoutMlDsaPublicKey_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setClassicalPublicKey(ed25519PublicKey)
                .build());
  }

  @Test
  public void buildWithoutClassicalPublicKey_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .build());
  }

  @Test
  public void parametersNoPrefix_withId_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();

    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ed25519PublicKey)
                .setIdRequirement(123)
                .build());
  }

  @Test
  public void parametersTink_withoutId_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();

    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ed25519PublicKey)
                .build());
  }

  @Test
  public void mlDsaWrongVariant_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P384)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.TINK))
            .setSerializedPublicKey(FAKE_MLDSA87_PUBLIC_KEY_BYTES)
            .setIdRequirement(123)
            .build();

    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey ecdsaPublicKey =
        EcdsaPublicKey.builder().setParameters(ecdsaParameters).setPublicPoint(P384_POINT).build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ecdsaPublicKey)
                .build());
  }

  @Test
  public void mlDsaInstanceMismatch_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();

    // ML_DSA_87 key doesn't match ML_DSA_65 parameter.
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA87_PUBLIC_KEY_BYTES)
            .build();

    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ed25519PublicKey)
                .build());
  }

  @Test
  public void classicalAlgorithmMismatch_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    // TINK variant for Ed25519 is incorrect for this composite parameter.
    // The required variant is NO_PREFIX.
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.TINK, FAKE_ED25519_PUBLIC_KEY_BYTES, 123);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setMlDsaPublicKey(mlDsaPublicKey)
                .setClassicalPublicKey(ed25519PublicKey)
                .build());
  }

  @Test
  public void testSimpleEqualsKey() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    CompositeMlDsaPublicKey key1 =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPublicKey key2 =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPublicKey keyDifferentId =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .setIdRequirement(456)
            .build();
    // Also test it with NO_PREFIX
    CompositeMlDsaParameters parametersNoPrefix =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    CompositeMlDsaPublicKey keyNoPrefix =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parametersNoPrefix)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .build();

    assertThat(key1.equalsKey(key2)).isTrue();
    assertThat(key1.equalsKey(keyDifferentId)).isFalse();
    assertThat(key1.equalsKey(keyNoPrefix)).isFalse();
    assertThat(key1.equalsKey(ed25519PublicKey)).isFalse();
  }

  @Test
  public void testFullEqualsKey() throws Exception {
    CompositeMlDsaParameters parameters1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey1 =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey1 =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    CompositeMlDsaParameters parameters2 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    MlDsaPublicKey mlDsaPublicKey2 =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .build();
    Ed25519PublicKey ed25519PublicKey2 =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

    CompositeMlDsaPublicKey key1 =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters1)
            .setMlDsaPublicKey(mlDsaPublicKey1)
            .setClassicalPublicKey(ed25519PublicKey1)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPublicKey key2 =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters2)
            .setMlDsaPublicKey(mlDsaPublicKey2)
            .setClassicalPublicKey(ed25519PublicKey2)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPublicKey keyDifferentId =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters1)
            .setMlDsaPublicKey(mlDsaPublicKey1)
            .setClassicalPublicKey(ed25519PublicKey1)
            .setIdRequirement(456)
            .build();
    // Also test it with NO_PREFIX
    CompositeMlDsaParameters parametersNoPrefix =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    CompositeMlDsaPublicKey keyNoPrefix =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parametersNoPrefix)
            .setMlDsaPublicKey(mlDsaPublicKey1)
            .setClassicalPublicKey(ed25519PublicKey1)
            .build();

    assertThat(key1.equalsKey(key2)).isTrue();
    assertThat(key1.equalsKey(keyDifferentId)).isFalse();
    assertThat(key1.equalsKey(keyNoPrefix)).isFalse();
    assertThat(key1.equalsKey(ed25519PublicKey1)).isFalse();
  }
}
