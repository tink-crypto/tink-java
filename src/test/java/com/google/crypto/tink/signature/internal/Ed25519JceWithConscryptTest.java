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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Random;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Ed25519JceWithConscryptTest {

  @Before
  public void useOnlyConscrypt() throws Exception {
    if (!Util.isAndroid()) {

      // Remove all providers.
      Provider[] providers = Security.getProviders();
      for (Provider provider : providers) {
        Security.removeProvider(provider.getName());
      }

      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void signAndVerify_worksIfSupported() throws Exception {
    Assume.assumeTrue(!Util.isAndroid());
    Assume.assumeTrue(Ed25519SignJce.isSupported());
    Assume.assumeTrue(Ed25519VerifyJce.isSupported());

    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519SignJce signer = new Ed25519SignJce(keyPair.getPrivateKey());
    Ed25519VerifyJce verifier = new Ed25519VerifyJce(keyPair.getPublicKey());
    byte[] msg = Random.randBytes(20);
    byte[] sig = signer.sign(msg);
    verifier.verify(sig, msg);

    // Test that Ed25519SignJce and Ed25519Sign are compatible.
    Ed25519Sign tinkSubtleSigner = new Ed25519Sign(keyPair.getPrivateKey());
    assertThat(sig).isEqualTo(tinkSubtleSigner.sign(msg));
  }
}
