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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class XAesGcmKeyTest {

  @Test
  public void buildNoPrefixVariantExplicitAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);
    XAesGcmKey key = XAesGcmKey.create(parameters, keyBytes, null);
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8);
    XAesGcmKey key = XAesGcmKey.create(parameters, keyBytes, 0x0708090a);
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void wrongIdRequirement_throws() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8), keyBytes, 1115));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8), keyBytes, null));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    SecretBytes keyBytesCopy =
        SecretBytes.copyFrom(
            keyBytes.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytesDiff = SecretBytes.randomBytes(32);
    XAesGcmParameters parametersNoPrefix =
        XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 12);
    XAesGcmParameters parametersTink = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes",
            XAesGcmKey.create(parametersNoPrefix, keyBytes, null),
            XAesGcmKey.create(parametersNoPrefix, keyBytes, null),
            XAesGcmKey.create(parametersNoPrefix, keyBytesCopy, null))
        .addEqualityGroup(
            "No prefix, different key bytes",
            XAesGcmKey.create(parametersNoPrefix, keyBytesDiff, null))
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes32",
            XAesGcmKey.create(parametersTink, keyBytes, 1907),
            XAesGcmKey.create(parametersTink, keyBytesCopy, 1907))
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes32", XAesGcmKey.create(parametersTink, keyBytes, 1908))
        .doTests();
  }
}
