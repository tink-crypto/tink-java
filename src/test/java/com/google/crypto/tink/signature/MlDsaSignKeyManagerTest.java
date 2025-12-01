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

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.runner.RunWith;

// Test the functionality of MlDsaSignKeyManager that should work regardless of the
// Conscrypt's presence.
@RunWith(Theories.class)
public class MlDsaSignKeyManagerTest {
  @Test
  public void registerPair_throwsWithoutConscrypt() throws Exception {
    // Checking for when Conscrypt is absent.
    if (ConscryptUtil.providerOrNull() != null) {
      return;
    }

    assertThrows(GeneralSecurityException.class, MlDsaSignKeyManager::registerPair);
  }

  @Test
  public void getPublicKeyType_works() throws Exception {
    assertThat(MlDsaSignKeyManager.getPublicKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.MlDsaPublicKey");
  }

  @Test
  public void getPrivateKeyType_works() throws Exception {
    assertThat(MlDsaSignKeyManager.getPrivateKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey");
  }

  @Test
  public void registerPair_throwsInFips() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, MlDsaSignKeyManager::registerPair);
  }
}
