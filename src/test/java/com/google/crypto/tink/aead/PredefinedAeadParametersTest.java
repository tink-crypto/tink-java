// Copyright 2023 Google LLC
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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class PredefinedAeadParametersTest {
  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @DataPoints("AllParameters")
  public static final AeadParameters[] TEMPLATES =
      new AeadParameters[] {
        PredefinedAeadParameters.AES128_GCM,
        PredefinedAeadParameters.AES256_GCM,
        PredefinedAeadParameters.AES128_EAX,
        PredefinedAeadParameters.AES256_EAX,
        PredefinedAeadParameters.AES128_CTR_HMAC_SHA256,
        PredefinedAeadParameters.AES256_CTR_HMAC_SHA256,
        PredefinedAeadParameters.CHACHA20_POLY1305,
        PredefinedAeadParameters.XCHACHA20_POLY1305,
        PredefinedAeadParameters.XAES_256_GCM_192_BIT_NONCE,
      };

  @Theory
  public void testInstantiation(@FromDataPoints("AllParameters") AeadParameters parameters)
      throws Exception {
    Key key = KeysetHandle.generateNew(parameters).getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void testNotNull() {
    assertThat(PredefinedAeadParameters.AES128_GCM).isNotNull();
    assertThat(PredefinedAeadParameters.AES256_GCM).isNotNull();
    assertThat(PredefinedAeadParameters.AES128_EAX).isNotNull();
    assertThat(PredefinedAeadParameters.AES256_EAX).isNotNull();
    assertThat(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256).isNotNull();
    assertThat(PredefinedAeadParameters.AES256_CTR_HMAC_SHA256).isNotNull();
    assertThat(PredefinedAeadParameters.CHACHA20_POLY1305).isNotNull();
    assertThat(PredefinedAeadParameters.XCHACHA20_POLY1305).isNotNull();
    assertThat(PredefinedAeadParameters.XAES_256_GCM_192_BIT_NONCE).isNotNull();
    assertThat(PredefinedAeadParameters.XAES_256_GCM_192_BIT_NONCE_NO_PREFIX).isNotNull();
    assertThat(PredefinedAeadParameters.XAES_256_GCM_160_BIT_NONCE_NO_PREFIX).isNotNull();
    assertThat(PredefinedAeadParameters.X_AES_GCM_8_BYTE_SALT_NO_PREFIX).isNotNull();
  }
}
