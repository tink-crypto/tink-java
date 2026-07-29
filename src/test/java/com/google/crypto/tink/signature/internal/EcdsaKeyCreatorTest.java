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
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link EcdsaKeyCreator}. */
@RunWith(JUnit4.class)
public final class EcdsaKeyCreatorTest {

  @Test
  public void createKey_p256_works() throws Exception {
    EcdsaParameters parameters = PredefinedSignatureParameters.ECDSA_P256;
    EcdsaPrivateKey key = EcdsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_raw_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPrivateKey key = EcdsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_p384_works() throws Exception {
    EcdsaParameters parameters = PredefinedSignatureParameters.ECDSA_P384;
    EcdsaPrivateKey key = EcdsaKeyCreator.createKey(parameters, /* idRequirement= */ 456);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(456);
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_p521_works() throws Exception {
    EcdsaParameters parameters = PredefinedSignatureParameters.ECDSA_P521;
    EcdsaPrivateKey key = EcdsaKeyCreator.createKey(parameters, /* idRequirement= */ 789);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(789);
    assertThat(key.getPrivateValue()).isNotNull();
  }

  @Test
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    int numKeys = 2;
    if (TestUtil.isAndroid() || TestUtil.isTsan()) {
      numKeys = 2;
    }
    EcdsaParameters parameters = PredefinedSignatureParameters.ECDSA_P256;
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      EcdsaPrivateKey key = EcdsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }
}
