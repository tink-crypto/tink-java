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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class JwtMlDsaPrivateKeyTest {

  private static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Optional<String> kid;
    final Integer idRequirement;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        Optional<String> kid,
        @Nullable Integer idRequirement) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.kid = kid;
      this.idRequirement = idRequirement;
    }
  }

  @DataPoints("ml_dsa_private_keys")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.of("custom_kid"),
        /* idRequirement= */ null)
  };

  private static int getPublicKeySize(JwtMlDsaParameters.Algorithm algorithm) {
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return 1312;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return 1952;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return 2592;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
  }

  private static MlDsaParameters.MlDsaInstance getMlDsaInstance(
      JwtMlDsaParameters.Algorithm algorithm) {
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_44;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_65;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_87;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
  }

  private static JwtMlDsaPublicKey createPublicKey(TestVector testVector) throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);
    int keySize = getPublicKeySize(testVector.algorithm);
    Bytes publicKeyBytes = Bytes.copyFrom(Random.randBytes(keySize));
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);
    if (testVector.idRequirement != null) {
      builder.setIdRequirement(testVector.idRequirement);
    }
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(testVector.kid.get());
    }
    return builder.build();
  }

  @Theory
  @AccessesPartialKey
  public void create_withPrivateSeed_succeeds(@FromDataPoints("ml_dsa_private_keys") TestVector testVector)
      throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    SecretBytes privateSeed = SecretBytes.randomBytes(32);

    JwtMlDsaPrivateKey privateKey = JwtMlDsaPrivateKey.create(publicKey, privateSeed);

    assertThat(privateKey.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateSeed()).isEqualTo(privateSeed);
    assertThat(privateKey.getKid()).isEqualTo(testVector.kid);
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(testVector.idRequirement);

    MlDsaPrivateKey mlDsaPrivateKey = privateKey.getMlDsaPrivateKey();
    assertThat(mlDsaPrivateKey.getPublicKey()).isEqualTo(publicKey.getMlDsaPublicKey());
    assertThat(mlDsaPrivateKey.getPrivateSeed()).isEqualTo(privateSeed);
    assertThat(mlDsaPrivateKey.getParameters().getMlDsaInstance())
        .isEqualTo(getMlDsaInstance(testVector.algorithm));
    assertThat(mlDsaPrivateKey.getParameters().getVariant())
        .isEqualTo(MlDsaParameters.Variant.NO_PREFIX);
  }

  @Theory
  @AccessesPartialKey
  public void create_withMlDsaPrivateKey_succeeds(
      @FromDataPoints("ml_dsa_private_keys") TestVector testVector) throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    SecretBytes privateSeed = SecretBytes.randomBytes(32);
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(publicKey.getMlDsaPublicKey(), privateSeed);

    JwtMlDsaPrivateKey privateKey = JwtMlDsaPrivateKey.create(publicKey, mlDsaPrivateKey);

    assertThat(privateKey.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateSeed()).isEqualTo(privateSeed);
    assertThat(privateKey.getKid()).isEqualTo(testVector.kid);
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(testVector.idRequirement);
    assertThat(privateKey.getMlDsaPrivateKey()).isEqualTo(mlDsaPrivateKey);
  }

  @Test
  @AccessesPartialKey
  public void createWithMlDsaPrivateKey_mismatchedPublicKey_throws() throws Exception {
    TestVector testVector1 = testVectors[0];
    TestVector testVector2 = testVectors[1];

    JwtMlDsaPublicKey publicKey1 = createPublicKey(testVector1);
    JwtMlDsaPublicKey publicKey2 = createPublicKey(testVector2);

    SecretBytes privateSeed = SecretBytes.randomBytes(32);
    MlDsaPrivateKey mlDsaPrivateKey2 =
        MlDsaPrivateKey.createWithoutVerification(publicKey2.getMlDsaPublicKey(), privateSeed);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> JwtMlDsaPrivateKey.create(publicKey1, mlDsaPrivateKey2));
    assertThat(e).hasMessageThat().contains("public key does not match the private key");
  }

  @Test
  @AccessesPartialKey
  public void create_invalidPrivateSeedLength_throws() throws Exception {
    TestVector testVector = testVectors[0];
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    SecretBytes shortSeed = SecretBytes.randomBytes(31);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> JwtMlDsaPrivateKey.create(publicKey, shortSeed));
    assertThat(e).hasMessageThat().contains("Incorrect private seed size for ML-DSA");
  }

  @Test
  @AccessesPartialKey
  public void testEqualities() throws Exception {
    JwtMlDsaParameters mlDsa44Ignored =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes mlDsa44Bytes1 = Bytes.copyFrom(Random.randBytes(1312));
    JwtMlDsaPublicKey publicKeyMlDsa44Ignored =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa44Ignored)
            .setPublicKeyBytes(mlDsa44Bytes1)
            .build();

    JwtMlDsaParameters mlDsa44Custom =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKeyMlDsa44Custom1 =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa44Custom)
            .setPublicKeyBytes(mlDsa44Bytes1)
            .setCustomKid("custom1")
            .build();
    JwtMlDsaPublicKey publicKeyMlDsa44Custom2 =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa44Custom)
            .setPublicKeyBytes(mlDsa44Bytes1)
            .setCustomKid("custom2")
            .build();

    JwtMlDsaParameters mlDsa44Base64 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKeyMlDsa44Base64A =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa44Base64)
            .setPublicKeyBytes(mlDsa44Bytes1)
            .setIdRequirement(1)
            .build();
    JwtMlDsaPublicKey publicKeyMlDsa44Base64B =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa44Base64)
            .setPublicKeyBytes(mlDsa44Bytes1)
            .setIdRequirement(2)
            .build();

    JwtMlDsaParameters mlDsa65Ignored =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);
    Bytes mlDsa65Bytes1 = Bytes.copyFrom(Random.randBytes(1952));
    JwtMlDsaPublicKey publicKeyMlDsa65Ignored =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsa65Ignored)
            .setPublicKeyBytes(mlDsa65Bytes1)
            .build();

    SecretBytes seed1 = SecretBytes.randomBytes(32);
    SecretBytes seed2 = SecretBytes.randomBytes(32);

    new KeyTester()
        .addEqualityGroup(
            "ML-DSA-44 Ignored seed 1",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Ignored, seed1),
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Ignored, seed1))
        .addEqualityGroup(
            "ML-DSA-44 Ignored seed 2",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Ignored, seed2))
        .addEqualityGroup(
            "ML-DSA-65 Ignored seed 1",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa65Ignored, seed1))
        .addEqualityGroup(
            "ML-DSA-44 Custom 1",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Custom1, seed1))
        .addEqualityGroup(
            "ML-DSA-44 Custom 2",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Custom2, seed1))
        .addEqualityGroup(
            "ML-DSA-44 Base64 1",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Base64A, seed1))
        .addEqualityGroup(
            "ML-DSA-44 Base64 2",
            JwtMlDsaPrivateKey.create(publicKeyMlDsa44Base64B, seed1))
        .addEqualityGroup("different key class", ChaCha20Poly1305Key.create(seed1))
        .doTests();
  }
}
