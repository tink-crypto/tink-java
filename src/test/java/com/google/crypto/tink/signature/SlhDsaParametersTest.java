// Copyright 2025 Google LLC
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

import com.google.crypto.tink.signature.SlhDsaParameters.HashType;
import com.google.crypto.tink.signature.SlhDsaParameters.SignatureType;
import com.google.crypto.tink.signature.SlhDsaParameters.Variant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SlhDsaParametersTest {

  @Test
  public void createSlhDsaWithSha2And128S_tinkVariant_works() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
    assertThat(parameters.getHashType()).isEqualTo(HashType.SHA2);
    assertThat(parameters.getSignatureType()).isEqualTo(SignatureType.SMALL_SIGNATURE);
    assertThat(parameters.getPrivateKeySize()).isEqualTo(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void createSlhDsaWithSha2And128S_noPrefixVariant_works() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
    assertThat(parameters.getHashType()).isEqualTo(HashType.SHA2);
    assertThat(parameters.getSignatureType()).isEqualTo(SignatureType.SMALL_SIGNATURE);
    assertThat(parameters.getPrivateKeySize()).isEqualTo(64);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void equalsAndEqualHashCode() throws Exception {
    SlhDsaParameters parameters1 = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaParameters parameters2 = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void notEqualAndNotEqualHashCode() throws Exception {
    SlhDsaParameters parameters1 = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaParameters parameters2 = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
