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

package com.google.crypto.tink.signature.internal;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EcdsaSignJce and EcdsaVerifyJce in FIPS mode.
 *
 * <p>This test should be run with the <code>--use_only_fips=true</code>, both with the BoringCrypto
 * FIPS module enabled and disabled with <code>--define=BORINGSSL_FIPS=0</code>.
 */
@RunWith(JUnit4.class)
public final class EcdsaSignVerifyFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  private static final SignatureTestVector[] testVectors = EcdsaTestUtil.createEcdsaTestVectors();

  @Test
  public void createWorksIfFipsModuleAvailable() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    for (SignatureTestVector testVector : testVectors) {
      PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) testVector.getPrivateKey());
      byte[] signature = signer.sign(testVector.getMessage());
      PublicKeyVerify verifier =
          EcdsaVerifyJce.create((EcdsaPublicKey) testVector.getPrivateKey().getPublicKey());
      verifier.verify(signature, testVector.getMessage());
    }
  }

  @Test
  public void createThrowsIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.fipsModuleAvailable());
    for (SignatureTestVector testVector : testVectors) {
      assertThrows(
          GeneralSecurityException.class,
          () -> EcdsaSignJce.create((EcdsaPrivateKey) testVector.getPrivateKey()));
      assertThrows(
          GeneralSecurityException.class,
          () -> EcdsaVerifyJce.create((EcdsaPublicKey) testVector.getPrivateKey().getPublicKey()));
    }
  }

  @Test
  public void constructorsWorkIfFipsModuleAvailable() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EllipticCurves.getNistP256Params());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    byte[] message = "Hello".getBytes(UTF_8);

    EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER);
    byte[] signature = signer.sign(message);

    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, HashType.SHA256, EcdsaEncoding.DER);
    verifier.verify(signature, message);
  }

  @Test
  public void constructorsDontValidateHashFunctionType() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    // Using Curve P521 with SHA256 is not allowed by the FIPS 140-2, see
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf Page 21.
    //
    // This is currently not enforced.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EllipticCurves.getNistP521Params());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    byte[] message = "Hello".getBytes(UTF_8);

    EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER);
    byte[] signature = signer.sign(message);

    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, HashType.SHA256, EcdsaEncoding.DER);
    verifier.verify(signature, message);
  }

  @Test
  public void constructorThrowsIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.fipsModuleAvailable());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EllipticCurves.getNistP256Params());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    assertThrows(
        GeneralSecurityException.class,
        () -> new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER));
    assertThrows(
        GeneralSecurityException.class,
        () -> new EcdsaVerifyJce(pub, HashType.SHA256, EcdsaEncoding.DER));
  }
}
