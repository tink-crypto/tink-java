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
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaParameters.Variant;
import com.google.crypto.tink.signature.SlhDsaPrivateKey;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link SlhDsaKeyCreator}. */
@RunWith(JUnit4.class)
public final class SlhDsaKeyCreatorTest {

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
  public void createKey_tink_works() throws Exception {
    if (!SlhDsaVerifyConscrypt.isSupported()) {
      return;
    }
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPrivateKey key = SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void createKey_raw_works() throws Exception {
    if (!SlhDsaVerifyConscrypt.isSupported()) {
      return;
    }
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPrivateKey key = SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void callingCreateTwice_createsDifferentKeys() throws Exception {
    if (!SlhDsaVerifyConscrypt.isSupported()) {
      return;
    }
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPrivateKey key0 = SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);
    SlhDsaPrivateKey key1 = SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertFalse(key0.equalsKey(key1));
  }

  @Test
  public void createKey_conscryptNotSupported_throws() throws Exception {
    if (SlhDsaVerifyConscrypt.isSupported()) {
      return;
    }
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    assertThrows(
        GeneralSecurityException.class,
        () -> SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
  }
}
