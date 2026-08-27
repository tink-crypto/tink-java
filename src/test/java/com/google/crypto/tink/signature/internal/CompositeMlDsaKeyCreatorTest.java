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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.Variant;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CompositeMlDsaKeyCreator}. */
@RunWith(JUnit4.class)
public class CompositeMlDsaKeyCreatorTest {

  @Before
  public void setUp() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void createKey_mlDsa44_ed25519_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa65_ed25519_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.TINK)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 0x12345678);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x12345678);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa44_rsa2048pss_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa44_rsa2048pkcs1_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa65_rsa3072pkcs1_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa65_rsa4096pkcs1_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa87_rsa3072pss_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_mlDsa87_rsa4096pss_works() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getIdRequirementOrNull()).isNull();

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] signature = signer.sign(data);
    verifier.verify(signature, data);
  }

  @Test
  public void createKey_differentKeysGenerated() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();

    CompositeMlDsaPrivateKey key0 =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);
    CompositeMlDsaPrivateKey key1 =
        CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertFalse(key0.equalsKey(key1));
  }

  @Test
  public void createKey_idRequirementSetForNoPrefix_throws() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 0x12345678));
  }

  @Test
  public void createKey_idRequirementNotSetForTink_throws() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  public void createKey_throwsInFips() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  public void createKey_compositeMlDsaNotSupported_throws() throws Exception {
    Assume.assumeFalse(CompositeMlDsaVerifyConscrypt.isSupported());
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .setVariant(Variant.NO_PREFIX)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  public void createKey_ecdsa_throws() throws Exception {
    assumeTrue(CompositeMlDsaVerifyConscrypt.isSupported());

    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
            .setVariant(Variant.NO_PREFIX)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }
}
