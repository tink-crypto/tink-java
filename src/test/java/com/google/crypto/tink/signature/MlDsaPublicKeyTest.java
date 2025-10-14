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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MlDsaPublicKeyTest {

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;
  private static final MlDsaParameters NO_PREFIX_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);
  private static final MlDsaParameters TINK_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK);
  private static final Bytes FAKE_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA65_PUBLIC_KEY_BYTES)));
  private static final Bytes SHORT_PUBLIC_KEY =
      Bytes.copyFrom(new byte[MLDSA65_PUBLIC_KEY_BYTES - 1]);
  private static final Bytes LONG_PUBLIC_KEY =
      Bytes.copyFrom(new byte[MLDSA65_PUBLIC_KEY_BYTES + 1]);

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    MlDsaPublicKey key =
        MlDsaPublicKey.builder()
            .setParameters(NO_PREFIX_PARAMS)
            .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
            .build();

    assertThat(key.getParameters()).isEqualTo(NO_PREFIX_PARAMS);
    assertThat(key.getSerializedPublicKey()).isEqualTo(FAKE_PUBLIC_KEY_BYTES);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    MlDsaPublicKey key =
        MlDsaPublicKey.builder()
            .setParameters(TINK_PARAMS)
            .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x66AABBCC)
            .build();

    assertThat(key.getParameters()).isEqualTo(TINK_PARAMS);
    assertThat(key.getSerializedPublicKey()).isEqualTo(FAKE_PUBLIC_KEY_BYTES);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> MlDsaPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> MlDsaPublicKey.builder().setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES).build());
  }

  @Test
  public void buildWithoutSerializedPublicKey_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> MlDsaPublicKey.builder().setParameters(NO_PREFIX_PARAMS).build());
  }

  @Test
  public void parametersNoPrefix_withId_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MlDsaPublicKey.builder()
                .setParameters(NO_PREFIX_PARAMS)
                .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
                .setIdRequirement(123)
                .build());
  }

  @Test
  public void parametersTink_withoutId_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MlDsaPublicKey.builder()
                .setParameters(TINK_PARAMS)
                .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
                .build());
  }

  @Test
  public void incorrectPublicKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MlDsaPublicKey.builder()
                .setParameters(NO_PREFIX_PARAMS)
                .setSerializedPublicKey(SHORT_PUBLIC_KEY)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MlDsaPublicKey.builder()
                .setParameters(NO_PREFIX_PARAMS)
                .setSerializedPublicKey(LONG_PUBLIC_KEY)
                .build());
  }

  @Test
  public void incorrectInstance_fails() throws Exception {
    MlDsaParameters mlDsa87Parameters =
        MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            MlDsaPublicKey.builder()
                .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
                .setParameters(mlDsa87Parameters)
                .setIdRequirement(123)
                .build());
  }
}
