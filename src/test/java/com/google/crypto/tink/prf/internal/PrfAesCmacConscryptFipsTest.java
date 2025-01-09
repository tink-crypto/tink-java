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

package com.google.crypto.tink.prf.internal;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfAesCmacConscryptFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void create_useOnlyFipsIsTrue_throwsException() throws Exception {
    int keySize = 16;
    AesCmacPrfKey key =
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(keySize),
                SecretBytes.copyFrom(
                    Random.randBytes(keySize),
                    InsecureSecretKeyAccess.get()));

    assertThrows(GeneralSecurityException.class, () -> PrfAesCmacConscrypt.create(key));
  }
}
