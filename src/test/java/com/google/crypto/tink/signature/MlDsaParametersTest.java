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

import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MlDsaParametersTest {

  @Test
  public void createMlDsa65() {
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK);

    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_65);
    assertThat(parameters.getVariant()).isEqualTo(Variant.TINK);
  }

  @Test
  public void createMlDsa87() {
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX);

    assertThat(parameters.getMlDsaInstance()).isEqualTo(MlDsaInstance.ML_DSA_87);
    assertThat(parameters.getVariant()).isEqualTo(Variant.NO_PREFIX);
  }

  @Test
  public void equalsAndEqualHashCode() {
    MlDsaParameters parameters1 = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK);
    MlDsaParameters parameters2 = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK);

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void notEqualAndNotEqualHashCode() {
    MlDsaParameters parameters1 = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK);
    MlDsaParameters parameters2 =
        MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX);

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
