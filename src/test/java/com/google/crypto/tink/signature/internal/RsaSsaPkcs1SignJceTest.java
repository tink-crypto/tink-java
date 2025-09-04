// Copyright 2018 Google Inc.
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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPkcs1SignJce.  */
@RunWith(Theories.class)
public class RsaSsaPkcs1SignJceTest {

  @BeforeClass
  public static void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test RSA PKCS1.5 sign in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(
        GeneralSecurityException.class, () -> RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) allTestVectors[0].getPrivateKey()));
  }

  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPkcs1VerifyJce.create(
            (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeySign signer =
        RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) testVector.getPrivateKey());
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        RsaSsaPkcs1VerifyJce.create(
            (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  @Theory
  public void test_validateSignatureInTestVectorWithWrongMessage_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPkcs1VerifyJce.create(
            (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey());
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {0x01});
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  @Theory
  public void createWithProvider_nullProvider_throws() throws Exception {
    SignatureTestVector testVector = allTestVectors[0];
    assertThrows(
        NullPointerException.class,
        () ->
            RsaSsaPkcs1SignJce.createWithProvider(
                (RsaSsaPkcs1PrivateKey) testVector.getPrivateKey(), null));
  }

  @Theory
  public void createWithProvider_worksWithDefaultProvider() throws Exception {
    Provider defaultProvider = Signature.getInstance("SHA256withRSA").getProvider();
    SignatureTestVector testVector = allTestVectors[0];

    PublicKeySign signer =
        RsaSsaPkcs1SignJce.createWithProvider(
            (RsaSsaPkcs1PrivateKey) testVector.getPrivateKey(), defaultProvider);
    byte[] signature = signer.sign(testVector.getMessage());
    // RSA-SSA-PKCS1.5 signatures are deterministic.
    assertThat(signature).isEqualTo(testVector.getSignature());
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] allTestVectors =
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors();
}
