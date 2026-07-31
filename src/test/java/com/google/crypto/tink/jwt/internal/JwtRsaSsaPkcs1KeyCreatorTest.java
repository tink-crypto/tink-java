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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.jwt.JwtRsaSsaPkcs1Parameters;
import com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JwtRsaSsaPkcs1KeyCreator}. */
@RunWith(JUnit4.class)
public final class JwtRsaSsaPkcs1KeyCreatorTest {

  @Test
  public void createKey_2048_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPkcs1PrivateKey key =
        JwtRsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getModulus().bitLength()).isEqualTo(2048);
    assertThat(key.getPrimeP()).isNotNull();
    assertThat(key.getPrimeQ()).isNotNull();
  }

  @Test
  public void createKey_3072_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtRsaSsaPkcs1PrivateKey key =
        JwtRsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getKid()).isPresent();
    assertThat(key.getPublicKey().getModulus().bitLength()).isEqualTo(3072);
    assertThat(key.getPrimeP()).isNotNull();
    assertThat(key.getPrimeQ()).isNotNull();
  }

  @Test
  public void createKey_4096_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtRsaSsaPkcs1PrivateKey key =
        JwtRsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ 456);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(456);
    assertThat(key.getPublicKey().getModulus().bitLength()).isEqualTo(4096);
    assertThat(key.getPrimeP()).isNotNull();
    assertThat(key.getPrimeQ()).isNotNull();
  }

  @Test
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    int numKeys = 2;
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .build();
    Set<BigInteger> primes = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtRsaSsaPkcs1PrivateKey key =
          JwtRsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ null);
      primes.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      primes.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(primes).hasSize(2 * numKeys);
  }
}
