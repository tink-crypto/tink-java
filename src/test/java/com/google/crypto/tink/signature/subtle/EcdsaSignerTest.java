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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link EcdsaSigner}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class EcdsaSignerTest {

  @Theory
  public void sign_computesValidSignature(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    EcdsaPrivateKey key = (EcdsaPrivateKey) testVector.getPrivateKey();

    PublicKeySign signer = EcdsaSigner.create(key);
    byte[] signature = signer.sign(testVector.getMessage());

    PublicKeyVerify verifier = EcdsaVerifier.create(key.getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> EcdsaSigner.create(null));
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] testVectors = EcdsaTestUtil.createEcdsaTestVectors();
}
