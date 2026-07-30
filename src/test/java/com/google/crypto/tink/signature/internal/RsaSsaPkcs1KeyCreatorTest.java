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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RsaSsaPkcs1KeyCreator}. */
@RunWith(JUnit4.class)
public final class RsaSsaPkcs1KeyCreatorTest {

  @Test
  public void createKey_2048_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey key =
        RsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ null);

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
    RsaSsaPkcs1Parameters parameters = PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4;
    RsaSsaPkcs1PrivateKey key =
        RsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
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
    RsaSsaPkcs1Parameters parameters = PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4;
    RsaSsaPkcs1PrivateKey key =
        RsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ 456);

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
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    Set<BigInteger> primes = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      RsaSsaPkcs1PrivateKey key =
          RsaSsaPkcs1KeyCreator.createKey(parameters, /* idRequirement= */ null);
      primes.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      primes.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(primes).hasSize(2 * numKeys);
  }
}
