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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CompositeMlDsaPrivateKeyTest {

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;
  private static final Bytes FAKE_MLDSA65_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA65_PUBLIC_KEY_BYTES)));

  private static final int MLDSA87_PUBLIC_KEY_BYTES = 2592;
  private static final Bytes FAKE_MLDSA87_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA87_PUBLIC_KEY_BYTES)));

  private static final SecretBytes FAKE_MLDSA_SEED =
      SecretBytes.copyFrom(Hex.decode("03".repeat(32)), InsecureSecretKeyAccess.get());

  private static final Bytes FAKE_ED25519_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(
          Hex.decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"));

  private static final SecretBytes FAKE_ED25519_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(
          Hex.decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
          InsecureSecretKeyAccess.get());

  private static final ECPoint P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);

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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);
    CompositeMlDsaPublicKey expectedPublicKey =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .build();

    CompositeMlDsaPrivateKey key =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(ed25519PrivateKey)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPrivateKey().equalsKey(mlDsaPrivateKey)).isTrue();
    assertThat(key.getClassicalPrivateKey().equalsKey(ed25519PrivateKey)).isTrue();
    assertThat(key.getPublicKey().equalsKey(expectedPublicKey)).isTrue();
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
  }

  @Test
  public void buildTinkMlDsa65Ed25519AndGetProperties() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);
    CompositeMlDsaPublicKey expectedPublicKey =
        CompositeMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setMlDsaPublicKey(mlDsaPublicKey)
            .setClassicalPublicKey(ed25519PublicKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    CompositeMlDsaPrivateKey key =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(ed25519PrivateKey)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getMlDsaPrivateKey().equalsKey(mlDsaPrivateKey)).isTrue();
    assertThat(key.getClassicalPrivateKey().equalsKey(ed25519PrivateKey)).isTrue();
    assertThat(key.getPublicKey().equalsKey(expectedPublicKey)).isTrue();
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> CompositeMlDsaPrivateKey.builder().build());
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    CompositeMlDsaPrivateKey key1 =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(ed25519PrivateKey)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPrivateKey key2 =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(ed25519PrivateKey)
            .setIdRequirement(123)
            .build();
    CompositeMlDsaPrivateKey keyDifferentId =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(ed25519PrivateKey)
            .setIdRequirement(456)
            .build();

    assertThat(key1.equalsKey(key2)).isTrue();
    assertThat(key1.equalsKey(keyDifferentId)).isFalse();
    assertThat(key1.equalsKey(ed25519PrivateKey)).isFalse();
  }

  @Test
  public void buildWithTinkVariantMlDsaKey_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    MlDsaPublicKey mlDsaPublicKeyTink =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK))
            .setSerializedPublicKey(FAKE_MLDSA65_PUBLIC_KEY_BYTES)
            .setIdRequirement(123)
            .build();
    MlDsaPrivateKey mlDsaPrivateKeyTink =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKeyTink, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKeyTink)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .build());
  }

  @Test
  public void buildWithTinkVariantClassicalKey_fails() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKeyTink =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.TINK, FAKE_ED25519_PUBLIC_KEY_BYTES, 123);
    Ed25519PrivateKey ed25519PrivateKeyTink =
        Ed25519PrivateKey.create(ed25519PublicKeyTink, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .setClassicalPrivateKey(ed25519PrivateKeyTink)
                .build());
  }

  @Test
  public void buildWithUnsupportedAlgorithmCombination_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
                .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                .build());
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .build());
  }

  @Test
  public void buildWithoutMlDsaKey_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .build());
  }

  @Test
  public void buildWithoutClassicalKey_fails() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .build());
  }

  @Test
  public void buildWithNoPrefixParametersAndIdRequirement_fails() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .setIdRequirement(123)
                .build());
  }

  @Test
  public void buildWithTinkParametersAndWithoutIdRequirement_fails() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .build());
  }

  @Test
  public void buildWithMismatchedMlDsaKey_fails() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
            .build();
    MlDsaPublicKey mlDsaPublicKey87 =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    MlDsaParameters.MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(FAKE_MLDSA87_PUBLIC_KEY_BYTES)
            .build();
    MlDsaPrivateKey mlDsaPrivateKey87 =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey87, FAKE_MLDSA_SEED);
    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, FAKE_ED25519_PUBLIC_KEY_BYTES, null);
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(ed25519PublicKey, FAKE_ED25519_PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey87)
                .setClassicalPrivateKey(ed25519PrivateKey)
                .build());
  }

  @Test
  public void buildWithMismatchedClassicalKeyAlgorithm_fails() throws Exception {
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
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(mlDsaPublicKey, FAKE_MLDSA_SEED);

    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey ecdsaPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(ecdsaParameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey ecdsaPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(ecdsaPublicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaPrivateKey.builder()
                .setParameters(parameters)
                .setMlDsaPrivateKey(mlDsaPrivateKey)
                .setClassicalPrivateKey(ecdsaPrivateKey)
                .build());
  }
}
