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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssSignJce. */
@RunWith(Theories.class)
public class RsaSsaPssSignJceTest {

  private final RSAPrivateCrtKey toRsaPrivateCrtKey(RsaSsaPssPrivateKey key) throws Exception {
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

  private static HashType toEnumHashType(RsaSsaPssParameters.HashType hash) {
    if (hash == RsaSsaPssParameters.HashType.SHA256) {
      return HashType.SHA256;
    } else if (hash == RsaSsaPssParameters.HashType.SHA384) {
      return HashType.SHA384;
    } else if (hash == RsaSsaPssParameters.HashType.SHA512) {
      return HashType.SHA512;
    } else {
      throw new IllegalArgumentException("Unsupported hash: " + hash);
    }
  }

  @Test
  public void constructorValidatesHashType() throws Exception {
    SignatureTestVector testVector = SIGNATURE_TEST_VECTORS[0];
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    RSAPrivateCrtKey priv = toRsaPrivateCrtKey(key);

    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssSignJce(priv, HashType.SHA1, HashType.SHA1, 20));
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA1, 32));
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA384, 32));
  }

  /**
   * Tests that the verifier can verify a newly generated signature for the message and key in the
   * test vector.
   */
  @Theory
  public void createAndSign_works(@FromDataPoints("testVectors") SignatureTestVector testVector)
      throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    PublicKeySign signer = RsaSsaPssSignJce.create(key);
    byte[] signature = signer.sign(testVector.getMessage());

    // Test that the verifier can verify the signature.
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  @Theory
  public void constructorAndSign_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey testPrivateKey = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    RsaSsaPssPublicKey testPublicKey = testPrivateKey.getPublicKey();
    RsaSsaPssParameters testParameters = testPublicKey.getParameters();
    if (!testParameters.getVariant().equals(RsaSsaPssParameters.Variant.NO_PREFIX)) {
      // Constructor doesn't support output prefix.
      return;
    }
    RsaSsaPssSignJce signer =
        new RsaSsaPssSignJce(
            toRsaPrivateCrtKey(testPrivateKey),
            toEnumHashType(testParameters.getSigHashType()),
            toEnumHashType(testParameters.getMgf1HashType()),
            testParameters.getSaltLengthBytes());
    byte[] signature = signer.sign(testVector.getMessage());

    // Test that the verifier can verify the signature.
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(testPublicKey);
    verifier.verify(signature, testVector.getMessage());
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] SIGNATURE_TEST_VECTORS =
      RsaSsaPssTestUtil.createRsaPssTestVectors();
}
