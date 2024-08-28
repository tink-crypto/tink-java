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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class XAesGcmParametersTest {
  private static final XAesGcmParameters.Variant NO_PREFIX = XAesGcmParameters.Variant.NO_PREFIX;
  private static final XAesGcmParameters.Variant TINK = XAesGcmParameters.Variant.TINK;
  private static final XAesGcmParameters.Variant CRUNCHY = XAesGcmParameters.Variant.CRUNCHY;

  @Test
  public void buildParameters_noPrefix() throws Exception {
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.getSaltSizeBytes()).isEqualTo(8);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParameters_tink() throws Exception {
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    assertThat(parameters.getVariant()).isEqualTo(TINK);
    assertThat(parameters.getSaltSizeBytes()).isEqualTo(12);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParameters_crunchy() throws Exception {
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, 8);
    assertThat(parameters.getVariant()).isEqualTo(CRUNCHY);
    assertThat(parameters.getSaltSizeBytes()).isEqualTo(8);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParameters_invalidSaltSize_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 7));
    assertThrows(
        GeneralSecurityException.class,
        () -> XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 13));
  }

  @Test
  public void testEqualsAndEqualHashCode_noPrefix() throws Exception {
    XAesGcmParameters parametersNoPrefix0 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);
    XAesGcmParameters parametersNoPrefix1 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);
    assertThat(parametersNoPrefix0).isEqualTo(parametersNoPrefix1);
    assertThat(parametersNoPrefix0.hashCode()).isEqualTo(parametersNoPrefix1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_tink() throws Exception {
    XAesGcmParameters parametersTink0 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    XAesGcmParameters parametersTink1 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    assertThat(parametersTink0).isEqualTo(parametersTink1);
    assertThat(parametersTink0.hashCode()).isEqualTo(parametersTink1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_crunchy() throws Exception {
    XAesGcmParameters parametersCrunchy0 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, 11);
    XAesGcmParameters parametersCrunchy1 =
        XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, 11);
    assertThat(parametersCrunchy0).isEqualTo(parametersCrunchy1);
    assertThat(parametersCrunchy0.hashCode()).isEqualTo(parametersCrunchy1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_different() throws Exception {
    XAesGcmParameters parametersNoPrefix =
        XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);

    XAesGcmParameters parametersTink = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8);

    XAesGcmParameters parametersCrunchy =
        XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, 8);

    assertThat(parametersNoPrefix).isNotEqualTo(parametersTink);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersTink.hashCode());

    assertThat(parametersNoPrefix).isNotEqualTo(parametersCrunchy);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersTink).isNotEqualTo(parametersNoPrefix);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersNoPrefix.hashCode());

    assertThat(parametersTink).isNotEqualTo(parametersCrunchy);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersCrunchy).isNotEqualTo(parametersNoPrefix);
    assertThat(parametersCrunchy.hashCode()).isNotEqualTo(parametersNoPrefix.hashCode());

    assertThat(parametersCrunchy).isNotEqualTo(parametersTink);
    assertThat(parametersCrunchy.hashCode()).isNotEqualTo(parametersTink.hashCode());

    XAesGcmParameters parametersTinkWithDifferentSalt =
        XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    assertThat(parametersTink).isNotEqualTo(parametersTinkWithDifferentSalt);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersTinkWithDifferentSalt.hashCode());
  }
}
