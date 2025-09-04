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

package com.google.crypto.tink.subtle;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.TreeSet;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPkcs1SignJce. */
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
  public void constructor_worksWithAllSha2s() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    int keySize = 3072;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

    byte[] message = "Hello".getBytes(UTF_8);

    {
      // Sign with SHA256
      RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA256);
      byte[] signature = signer.sign(message);

      // Verify with JCE
      Signature verifier = Signature.getInstance("SHA256withRSA");
      verifier.initVerify(pub);
      verifier.update(message);
      assertTrue(verifier.verify(signature));
    }

    {
      // Sign with SHA384
      RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA384);
      byte[] signature = signer.sign(message);

      // Verify with JCE
      Signature verifier = Signature.getInstance("SHA384withRSA");
      verifier.initVerify(pub);
      verifier.update(message);
      assertTrue(verifier.verify(signature));
    }

    {
      // Sign with SHA512
      RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA512);
      byte[] signature = signer.sign(message);

      // Verify with JCE
      Signature verifier = Signature.getInstance("SHA512withRSA");
      verifier.initVerify(pub);
      verifier.update(message);
      assertTrue(verifier.verify(signature));
    }

    // SHA1 is not supported.
    assertThrows(GeneralSecurityException.class, () -> new RsaSsaPkcs1SignJce(priv, HashType.SHA1));
  }

  @Test
  public void testSignWithTheSameMessage() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.
    Assume.assumeFalse(
        TestUtil
            .isTsan()); // This test times out when running under thread sanitizer, so we just skip.

    int keySize = 4096;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

    byte[] msg = Random.randBytes(20);
    TreeSet<String> allSignatures = new TreeSet<>();
    RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA512);
    for (int i = 0; i < 100; i++) {
      byte[] sig = signer.sign(msg);
      allSignatures.add(Hex.encode(sig));
      // Verify with JCE's Signature.
      Signature verifier = Signature.getInstance("SHA512WithRSA");
      verifier.initVerify(pub);
      verifier.update(msg);
      if (!verifier.verify(sig)) {
        fail(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                Hex.encode(msg),
                Hex.encode(sig),
                Hex.encode(priv.getEncoded()),
                Hex.encode(pub.getEncoded())));
      }
    }
    // RSA SSA PKCS1 is deterministic, expect a unique signature for the same message.
    assertEquals(1, allSignatures.size());
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(3072);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

    assertThrows(
        GeneralSecurityException.class, () -> new RsaSsaPkcs1SignJce(priv, HashType.SHA512));
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

  @DataPoints("allTests")
  public static final SignatureTestVector[] allTestVectors =
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors();
}
