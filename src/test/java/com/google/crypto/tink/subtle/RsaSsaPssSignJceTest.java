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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssSignJce. */
@RunWith(Theories.class)
public class RsaSsaPssSignJceTest {

  private final RSAPrivateCrtKey getTestPrivateKey() throws Exception {
    SignatureTestVector testVector = SIGNATURE_TEST_VECTORS[0];
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    return (RSAPrivateCrtKey)
        keyFactory.generatePrivate(
            new RSAPrivateCrtKeySpec(
                key.getPublicKey().getModulus(),
                key.getParameters().getPublicExponent(),
                key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
  }

  private final RSAPublicKey getTestPublicKey() throws Exception {
    SignatureTestVector testVector = SIGNATURE_TEST_VECTORS[0];
    RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    return (RSAPublicKey)
        keyFactory.generatePublic(
            new RSAPublicKeySpec(key.getModulus(), key.getParameters().getPublicExponent()));
  }

  @Test
  public void constructorDoesNotSupportHashTypeSha1() throws Exception {
    RSAPrivateCrtKey priv = getTestPrivateKey();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new RsaSsaPssSignJce(priv, HashType.SHA1, HashType.SHA1, 20));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void signVerifyWithSha256() throws Exception {
    RSAPublicKey pub = getTestPublicKey();
    RSAPrivateCrtKey priv = getTestPrivateKey();

    // Sign with RsaSsaPssSignJce.
    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA256, 32);

    for (int i = 0; i < 1024; i++) {
      byte[] signature = signer.sign(message);
      // Verify with JCE's Signature.
      RsaSsaPssVerifyJce verifier =
          new RsaSsaPssVerifyJce(pub, HashType.SHA256, HashType.SHA256, 32);
      verifier.verify(signature, message);
    }
  }

  @Test
  public void signVerifyWithZeroSalt() throws Exception {
    RSAPublicKey pub = getTestPublicKey();
    RSAPrivateCrtKey priv = getTestPrivateKey();

    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA256, 0);
    byte[] signature = signer.sign(message);

    RsaSsaPssVerifyJce verifier = new RsaSsaPssVerifyJce(pub, HashType.SHA256, HashType.SHA256, 0);
    verifier.verify(signature, message);
  }

  @Test
  public void signVerifyWithSha384() throws Exception {
    RSAPublicKey pub = getTestPublicKey();
    RSAPrivateCrtKey priv = getTestPrivateKey();

    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA384, HashType.SHA384, 32);
    byte[] signature = signer.sign(message);

    RsaSsaPssVerifyJce verifier = new RsaSsaPssVerifyJce(pub, HashType.SHA384, HashType.SHA384, 32);
    verifier.verify(signature, message);
  }

  // TODO(b/182987934): Let constructor and key object behave the same way.
  // Currently, the constructor accepts two different hash types, but the key object does not.
  // We should make this consistent.
  @Test
  public void signVerifyUsingConstructorWithTwoDifferentHashTypes() throws Exception {
    RSAPublicKey pub = getTestPublicKey();
    RSAPrivateCrtKey priv = getTestPrivateKey();

    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA384, 32);
    byte[] signature = signer.sign(message);

    RsaSsaPssVerifyJce verifier = new RsaSsaPssVerifyJce(pub, HashType.SHA256, HashType.SHA384, 32);
    verifier.verify(signature, message);
  }

  /**
   * Tests that the verifier can verify a newly generated signature for the message and key in the
   * test vector.
   */
  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    PublicKeySign signer = RsaSsaPssSignJce.create(key);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] SIGNATURE_TEST_VECTORS =
      RsaSsaPssTestUtil.createRsaPssTestVectors();
}
