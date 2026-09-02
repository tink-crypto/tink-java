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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RsaSsaPssKeyCreator}. */
@RunWith(JUnit4.class)
public final class RsaSsaPssKeyCreatorTest {

  @Test
  public void createKey_2048_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPrivateKey key = RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ null);

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
    RsaSsaPssParameters parameters =
        PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4;
    RsaSsaPssPrivateKey key = RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ 123);

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
    RsaSsaPssParameters parameters =
        PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4;
    RsaSsaPssPrivateKey key = RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ 456);

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
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    Set<BigInteger> primes = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      RsaSsaPssPrivateKey key =
          RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ null);
      primes.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      primes.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(primes).hasSize(2 * numKeys);
  }

  @Test
  public void createKey_withProvider_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    Provider provider = KeyPairGenerator.getInstance("RSA").getProvider();
    RsaSsaPssParameters parameters =
        PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4;
    RsaSsaPssPrivateKey key =
        RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ 123, provider);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPublicKey().getModulus().bitLength()).isEqualTo(3072);
    assertThat(key.getPrimeP()).isNotNull();
    assertThat(key.getPrimeQ()).isNotNull();
  }

  @Test
  public void createKey_nullProvider_works() throws Exception {
    if (TestUtil.isTsan()) {
      // Key creation is too slow in Tsan.
      return;
    }
    RsaSsaPssParameters parameters =
        PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4;
    RsaSsaPssPrivateKey key =
        RsaSsaPssKeyCreator.createKey(parameters, /* idRequirement= */ 123, /* provider= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPublicKey().getModulus().bitLength()).isEqualTo(3072);
    assertThat(key.getPrimeP()).isNotNull();
    assertThat(key.getPrimeQ()).isNotNull();
  }
}
