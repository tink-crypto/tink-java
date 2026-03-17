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

import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.Variant;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CompositeMlDsaParametersTest {

  @Test
  public void build_mldsa65_ed25519_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ED25519);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa65_ecdsaP256_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
            .setVariant(Variant.TINK)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ECDSA_P256);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void build_mldsa65_ecdsaP384_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ECDSA_P384);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa65_rsa3072Pss_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .setVariant(Variant.TINK)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA3072_PSS);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void build_mldsa65_rsa3072Pkcs1_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA3072_PKCS1);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa65_rsa4096Pss_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .setVariant(Variant.TINK)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA4096_PSS);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void build_mldsa65_rsa4096Pkcs1_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA4096_PKCS1);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa87_ecdsaP384_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_87);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ECDSA_P384);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa87_ecdsaP521_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
            .setVariant(Variant.TINK)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_87);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ECDSA_P521);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void build_mldsa87_rsa3072Pss_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_87);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA3072_PSS);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_mldsa87_rsa4096Pss_works() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .setVariant(Variant.TINK)
            .build();
    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_87);
    assertThat(parameters.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA4096_PSS);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void build_variantNotSet_defaultsToNoPrefix() throws Exception {
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void build_missingMlDsaInstance_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
                .build());
  }

  @Test
  public void build_missingClassicalAlgorithm_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder().setMlDsaInstance(MlDsaInstance.ML_DSA_65).build());
  }

  @Test
  public void build_mldsa65_incompatibleAlgorithm_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521) // Incompatible
                .build());
  }

  @Test
  public void build_mldsa87_ed25519_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                .setClassicalAlgorithm(ClassicalAlgorithm.ED25519) // Incompatible
                .build());
  }

  @Test
  public void build_mldsa87_rsa3072Pkcs1_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1) // Incompatible
                .build());
  }

  @Test
  public void build_mldsa87_rsa4096Pkcs1_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1) // Incompatible
                .build());
  }

  @Test
  public void build_mldsa87_ecdsaP256_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            CompositeMlDsaParameters.builder()
                .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256) // Incompatible
                .build());
  }

  @Test
  public void equalsAndHashCode() throws Exception {
    CompositeMlDsaParameters params1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
            .setVariant(Variant.TINK)
            .build();
    CompositeMlDsaParameters params2 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
            .setVariant(Variant.TINK)
            .build();
    CompositeMlDsaParameters params3 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();
    CompositeMlDsaParameters params4 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
            .setVariant(Variant.TINK)
            .build();
    CompositeMlDsaParameters params5 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
            .setVariant(Variant.NO_PREFIX)
            .build();

    assertThat(params1).isEqualTo(params2);
    assertThat(params1.hashCode()).isEqualTo(params2.hashCode());

    assertThat(params1).isNotEqualTo(params3);
    assertThat(params1.hashCode()).isNotEqualTo(params3.hashCode());
    assertThat(params1).isNotEqualTo(params4);
    assertThat(params1.hashCode()).isNotEqualTo(params4.hashCode());
    assertThat(params1).isNotEqualTo(params5);
    assertThat(params1.hashCode()).isNotEqualTo(params5.hashCode());
  }
}
