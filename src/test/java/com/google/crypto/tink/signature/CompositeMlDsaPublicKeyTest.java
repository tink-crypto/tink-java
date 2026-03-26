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

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;
  private static final Bytes FAKE_MLDSA65_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA65_PUBLIC_KEY_BYTES)));

  private static final int MLDSA87_PUBLIC_KEY_BYTES = 2592;
  private static final Bytes FAKE_MLDSA87_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA87_PUBLIC_KEY_BYTES)));

  private static final Bytes FAKE_ED25519_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("02".repeat(32)));

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
        EcdsaPublicKey.builder()
            .setParameters(ecdsaParameters)
            .setPublicPoint(P384_POINT)
            .build();

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
        EcdsaPublicKey.builder()
            .setParameters(ecdsaParameters)
            .setPublicPoint(P384_POINT)
            .build();

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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
  public void testEqualsKey() throws Exception {
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
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);

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
}
