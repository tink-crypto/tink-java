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
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link Ed25519Signer}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class Ed25519SignerTest {

  @Theory
  public void sign_outputsSameSignatureAsInTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();

    PublicKeySign signer = Ed25519Signer.create(key);
    byte[] signature = signer.sign(testVector.getMessage());
    // Ed25519 is deterministic, so signature must be the same as in the test vector.
    assertThat(signature).isEqualTo(testVector.getSignature());
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] testVectors =
      Ed25519TestUtil.createEd25519TestVectors();
}
