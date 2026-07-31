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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JwtEcdsaKeyCreator}. */
@RunWith(JUnit4.class)
public final class JwtEcdsaKeyCreatorTest {

  @Test
  public void createKey_es256_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    JwtEcdsaPrivateKey key =
        JwtEcdsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getPublicPoint()).isNotNull();
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_es384_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtEcdsaPrivateKey key =
        JwtEcdsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getKid()).isPresent();
    assertThat(key.getPublicKey().getPublicPoint()).isNotNull();
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_es512_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    JwtEcdsaPrivateKey key =
        JwtEcdsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getPublicPoint()).isNotNull();
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_customKidStrategy_throws() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    int numKeys = 2;
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtEcdsaPrivateKey key =
          JwtEcdsaKeyCreator.createKey(parameters, /* idRequirement= */ null);
      keys.add(key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }
}
