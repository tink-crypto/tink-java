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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link RsaSsaPssSignConscrypt}. */
@RunWith(Theories.class)
public class RsaSsaPssSignConscryptTest {

  @Before
  public void useConscrypt() throws Exception {
    if (!Util.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] testVectors =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Theory
  public void create_signAndVerifySignatureInTestVector_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    PublicKeySign signer =
        RsaSsaPssSignConscrypt.create((RsaSsaPssPrivateKey) testVector.getPrivateKey());
    PublicKeyVerify verifier =
        RsaSsaPssVerifyConscrypt.create(
            (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey());
    byte[] message = testVector.getMessage();
    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }

  @Theory
  public void createWithProvider_worksWithConscrypt(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    Provider conscryptProvider = ConscryptUtil.providerOrNull();
    if (conscryptProvider == null) {
      return;
    }
    PublicKeySign signer =
        RsaSsaPssSignConscrypt.createWithProvider(
            (RsaSsaPssPrivateKey) testVector.getPrivateKey(), conscryptProvider);
    PublicKeyVerify verifier =
        RsaSsaPssVerifyConscrypt.create(
            (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey());
    byte[] message = testVector.getMessage();
    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }
}
