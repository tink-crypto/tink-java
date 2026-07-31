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

package com.google.crypto.tink.jwt.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JwtMlDsaKeyCreator}. */
@RunWith(JUnit4.class)
public final class JwtMlDsaKeyCreatorTest {

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will fail or be skipped.
    }
  }

  @Test
  @AccessesPartialKey
  public void createKey_mlDsa44_tink_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPrivateKey key = JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getPublicKey().getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicKey().getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getPublicKey().getKid()).isPresent();
    assertThat(key.getPublicKey().getMlDsaPublicKey()).isNotNull();
    assertThat(key.getPrivateSeed()).isNotNull();
  }

  @Test
  @AccessesPartialKey
  public void createKey_mlDsa65_raw_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);
    JwtMlDsaPrivateKey key = JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicKey().getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getKid()).isEmpty();
    assertThat(key.getPublicKey().getMlDsaPublicKey()).isNotNull();
    assertThat(key.getPrivateSeed()).isNotNull();
  }

  @Test
  @AccessesPartialKey
  public void createKey_mlDsa87_tink_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_87);
    JwtMlDsaPrivateKey key = JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 789);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(789);
    assertThat(key.getPublicKey().getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicKey().getIdRequirementOrNull()).isEqualTo(789);
    assertThat(key.getPublicKey().getKid()).isPresent();
    assertThat(key.getPublicKey().getMlDsaPublicKey()).isNotNull();
    assertThat(key.getPrivateSeed()).isNotNull();
  }

  @Test
  public void createKey_ignoredKidStrategy_withKeyId_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
  }

  @Test
  public void createKey_base64KidStrategy_withoutKeyId_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  @AccessesPartialKey
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      return;
    }
    int numKeys = 2;
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    Set<Bytes> keys = new HashSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtMlDsaPrivateKey key = JwtMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(Bytes.copyFrom(key.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }
}
