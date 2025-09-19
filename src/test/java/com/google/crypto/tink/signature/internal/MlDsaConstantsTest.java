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

package com.google.crypto.tink.signature.internal;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MlDsaConstantsTest {

  @Test
  public void params_mlDsa65_succeeds() throws Exception {
    // Parameters from FIPS 204, Table 3
    MlDsaConstants.Params unused = new MlDsaConstants.Params(
        (byte) 6,
        (byte) 5,
        4,
        32 + 32 * 6 * 10,
        4,
        32 + 32 + 64 + 32 * ((6 + 5) * 4 + 13 * 6),
        MlDsaInstance.ML_DSA_65);
  }

  @Test
  public void params_mlDsa87_succeeds() throws Exception {
    // Parameters from FIPS 204, Table 3
    MlDsaConstants.Params unused = new MlDsaConstants.Params(
        (byte) 8,
        (byte) 7,
        2,
        32 + 32 * 8 * 10,
        3,
        32 + 32 + 64 + 32 * ((8 + 7) * 3 + 13 * 8),
        MlDsaInstance.ML_DSA_87);
  }

  @Test
  public void params_mlDsa65_invalidK_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 7,
                (byte) 5,
                4,
                32 + 32 * 7 * 10,
                4,
                32 + 32 + 64 + 32 * ((7 + 5) * 4 + 13 * 7),
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa65_invalidL_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 6,
                4,
                32 + 32 * 6 * 10,
                4,
                32 + 32 + 64 + 32 * ((6 + 6) * 4 + 13 * 6),
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa65_invalidEta_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 5,
                2,
                32 + 32 * 6 * 10,
                4,
                32 + 32 + 64 + 32 * ((6 + 5) * 4 + 13 * 6),
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa65_invalidBitlen2Eta_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 5,
                4,
                32 + 32 * 6 * 10,
                3,
                32 + 32 + 64 + 32 * ((6 + 5) * 3 + 13 * 6),
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa65_invalidPkLength_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 5,
                4,
                32 + 32 * 6 * 11, // Incorrect pkLength
                4,
                32 + 32 + 64 + 32 * ((6 + 5) * 4 + 13 * 6),
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa65_invalidSkLength_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 5,
                4,
                32 + 32 * 6 * 10,
                4,
                32 + 32 + 64 + 32 * ((6 + 5) * 4 + 13 * 6) + 1, // Incorrect skLength
                MlDsaInstance.ML_DSA_65));
  }

  @Test
  public void params_mlDsa87_invalidK_throws() throws Exception {
    assertThrows(
        IllegalStateException.class,
        () ->
            new MlDsaConstants.Params(
                (byte) 6,
                (byte) 7,
                2,
                32 + 32 * 6 * 10,
                3,
                32 + 32 + 64 + 32 * ((6 + 7) * 3 + 13 * 6),
                MlDsaInstance.ML_DSA_87));
  }
}
