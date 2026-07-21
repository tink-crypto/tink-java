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

import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.util.Bytes;
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
public final class JwtMlDsaPublicKeyTest {

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

  @DataPoints("ml_dsa_public_keys")
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

  @Theory
  public void build_succeeds(@FromDataPoints("ml_dsa_public_keys") TestVector testVector)
      throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);
    int keySize = getPublicKeySize(testVector.algorithm);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);
    if (testVector.idRequirement != null) {
      builder.setIdRequirement(testVector.idRequirement);
    }
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(testVector.kid.get());
    }
    JwtMlDsaPublicKey key = builder.build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKid()).isEqualTo(testVector.kid);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(testVector.idRequirement);

    MlDsaPublicKey mlDsaPublicKey = key.getMlDsaPublicKey();
    assertThat(mlDsaPublicKey.getSerializedPublicKey()).isEqualTo(publicKeyBytes);
    assertThat(mlDsaPublicKey.getParameters().getMlDsaInstance())
        .isEqualTo(getMlDsaInstance(testVector.algorithm));
    assertThat(mlDsaPublicKey.getParameters().getVariant())
        .isEqualTo(MlDsaParameters.Variant.NO_PREFIX);
  }

  @Test
  public void build_kidStrategyIgnored_setCustomKid_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(publicKeyBytes)
            .setCustomKid("customKid");

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e).hasMessageThat().contains("customKid must not be set for KidStrategy IGNORED");
  }

  @Test
  public void build_kidStrategyIgnored_setIdRequirement_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(publicKeyBytes)
            .setIdRequirement(123);

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e)
        .hasMessageThat()
        .contains("Cannot create key with ID requirement with parameters without ID requirement");
  }

  @Test
  public void build_kidStrategyCustom_missingCustomKid_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e).hasMessageThat().contains("customKid needs to be set for KidStrategy CUSTOM");
  }

  @Test
  public void build_kidStrategyCustom_setIdRequirement_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(publicKeyBytes)
            .setCustomKid("customKid")
            .setIdRequirement(123);

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e)
        .hasMessageThat()
        .contains("Cannot create key with ID requirement with parameters without ID requirement");
  }

  @Test
  public void build_kidStrategyBase64_missingIdRequirement_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e)
        .hasMessageThat()
        .contains("Cannot create key without ID requirement with parameters with ID requirement");
  }

  @Test
  public void build_kidStrategyBase64_setCustomKid_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(publicKeyBytes)
            .setIdRequirement(123)
            .setCustomKid("customKid");

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e)
        .hasMessageThat()
        .contains("customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
  }

  @Test
  public void build_mismatchedKeySize_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    int incorrectSize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_65);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[incorrectSize]);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setCustomKid("customKid")
            .setPublicKeyBytes(publicKeyBytes);

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e).hasMessageThat().contains("Incorrect public key size for ML-DSA-44");
  }

  @Test
  public void build_empty_throws() throws Exception {
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> JwtMlDsaPublicKey.builder().build());
    assertThat(e).hasMessageThat().contains("Cannot build without parameters");
  }

  @Test
  public void build_withoutParameters_throws() throws Exception {
    int keySize = getPublicKeySize(JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Bytes publicKeyBytes = Bytes.copyFrom(new byte[keySize]);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> JwtMlDsaPublicKey.builder().setPublicKeyBytes(publicKeyBytes).build());
    assertThat(e).hasMessageThat().contains("Cannot build without parameters");
  }

  @Theory
  public void build_withoutPublicKeyBytes_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setCustomKid("customKid");

    GeneralSecurityException e = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(e).hasMessageThat().contains("Cannot build without public key bytes");
  }

  @Test
  public void testEqualities() throws Exception {
    JwtMlDsaParameters mlDsa44Ignored =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters mlDsa44IgnoredCopy =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters mlDsa44Custom =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters mlDsa44Base64 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);

    JwtMlDsaParameters mlDsa65Ignored =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);

    Bytes mlDsa44Bytes1 = Bytes.copyFrom(new byte[1312]);
    Bytes mlDsa44Bytes1Copy = Bytes.copyFrom(new byte[1312]);
    byte[] mlDsa44Bytes2Raw = new byte[1312];
    mlDsa44Bytes2Raw[0] = 1;
    Bytes mlDsa44Bytes2 = Bytes.copyFrom(mlDsa44Bytes2Raw);

    Bytes mlDsa65Bytes = Bytes.copyFrom(new byte[1952]);

    new KeyTester()
        .addEqualityGroup(
            "ML-DSA-44 Ignored 1",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Ignored)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .build(),
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Ignored)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .build(),
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44IgnoredCopy)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .build(),
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Ignored)
                .setPublicKeyBytes(mlDsa44Bytes1Copy)
                .build())
        .addEqualityGroup(
            "ML-DSA-44 Ignored 2",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Ignored)
                .setPublicKeyBytes(mlDsa44Bytes2)
                .build())
        .addEqualityGroup(
            "ML-DSA-65 Ignored",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa65Ignored)
                .setPublicKeyBytes(mlDsa65Bytes)
                .build())
        .addEqualityGroup(
            "ML-DSA-44 Custom 1",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Custom)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .setCustomKid("custom1")
                .build())
        .addEqualityGroup(
            "ML-DSA-44 Custom 2",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Custom)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .setCustomKid("custom2")
                .build())
        .addEqualityGroup(
            "ML-DSA-44 Base64 1",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Base64)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .setIdRequirement(1)
                .build())
        .addEqualityGroup(
            "ML-DSA-44 Base64 2",
            JwtMlDsaPublicKey.builder()
                .setParameters(mlDsa44Base64)
                .setPublicKeyBytes(mlDsa44Bytes1)
                .setIdRequirement(2)
                .build())
        .doTests();
  }
}
