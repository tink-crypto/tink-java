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

package com.google.crypto.tink.signature.subtle;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link RsaSsaPssSigner}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public class RsaSsaPssSignerTest {

  /**
   * Tests that the verifier can verify a newly generated signature for the message and key in the
   * test vector.
   */
  @Theory
  public void createAndSign_works(@FromDataPoints("testVectors") SignatureTestVector testVector)
      throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    PublicKeySign signer = RsaSsaPssSigner.create(key);
    byte[] signature = signer.sign(testVector.getMessage());

    // Test that the verifier can verify the signature.
    PublicKeyVerify verifier = RsaSsaPssVerifier.create(key.getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] testVectors =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Test
  public void usesConscryptImplementationIfInstalled() throws Exception {
    Assume.assumeFalse(Util.isAndroid());
    Assume.assumeTrue(Conscrypt.isAvailable());

    SignatureTestVector testVector = testVectors[0];
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();

    PublicKeySign signer = RsaSsaPssSigner.create(key);
    assertThat(signer.getClass().getSimpleName()).isEqualTo("InternalImpl");

    Provider conscrypt = Conscrypt.newProvider();
    Security.addProvider(conscrypt);

    PublicKeySign signer2 = RsaSsaPssSigner.create(key);
    assertThat(signer2.getClass().getSimpleName()).isEqualTo("RsaSsaPssSignConscrypt");

    Security.removeProvider(conscrypt.getName());
  }
}
