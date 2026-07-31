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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link MlDsaKeyCreator}. */
@RunWith(JUnit4.class)
public final class MlDsaKeyCreatorTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    try {
      if (!Util.isAndroid() && Conscrypt.isAvailable()) {
        Security.addProvider(Conscrypt.newProvider());
      }
    } catch (Throwable cause) {
      throw new IllegalStateException("Setup failed", cause);
    }
  }

  @Test
  public void createKey_mlDsa44_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK);
    MlDsaPrivateKey key = MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void createKey_mlDsa65_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    MlDsaPrivateKey key = MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createKey_mlDsa87_works() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK);
    MlDsaPrivateKey key = MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 456);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(456);
  }

  @Test
  public void callingCreateTwice_createsDifferentKeys() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX);
    MlDsaPrivateKey key0 = MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);
    MlDsaPrivateKey key1 = MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertFalse(key0.equalsKey(key1));
  }

  @Test
  public void createKey_conscryptNotSupported_throws() throws Exception {
    if (MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK);
    assertThrows(
        GeneralSecurityException.class,
        () -> MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
  }
}
