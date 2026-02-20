// Copyright 2024 Google LLC
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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesCmacPrfWycheproofTestUtilTest {

  @Test
  public void readTestVectors_firstTestCaseIsCorrect() throws Exception {
    AesCmacPrfTestUtil.TestVector testVector =
        AesCmacPrfWycheproofTestUtil.readTestVectors().get(1);

    AesCmacPrfKey expectedKey =
        AesCmacPrfKey.create(
            AesCmacPrfParameters.create(16),
            SecretBytes.copyFrom(
                Hex.decode("e1e726677f4893890f8c027f9d8ef80d"), InsecureSecretKeyAccess.get()));
    assertThat(testVector.key().equalsKey(expectedKey)).isTrue();
    assertThat(testVector.data()).isEqualTo(Hex.decode("3f"));
    assertThat(testVector.outputLength()).isEqualTo(16);
    assertThat(testVector.output()).isEqualTo(Hex.decode("15f856bbed3b321952a584b3c4437a63"));
  }

  @Test
  public void readTestVectors_returnsCorrectNumberOfTestVectors() {
    List<AesCmacPrfTestUtil.TestVector> testVectors =
        AesCmacPrfWycheproofTestUtil.readTestVectors();

    assertThat(testVectors).hasSize(42);
  }
}
