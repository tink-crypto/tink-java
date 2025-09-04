// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for EcdsaVerifyJce. */
@RunWith(Theories.class)
public class EcdsaVerifyJceTest {

  @BeforeClass
  public static void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test ECDSA verify in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void constructor_unsupportedHash_throws() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    // Verify with EcdsaVerifyJce.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new EcdsaVerifyJce(pub, HashType.SHA1, EcdsaEncoding.DER));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  public static class TestCase {
    private final ECParameterSpec paramSpec;
    private final HashType hash;

    public ECParameterSpec paramSpec() {
      return paramSpec;
    }

    public HashType hash() {
      return hash;
    }

    public TestCase(ECParameterSpec paramSpec, HashType hash) {
      this.paramSpec = paramSpec;
      this.hash = hash;
    }
  }

  @DataPoints("testCases")
  public static final TestCase[] testCases = {
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA384),
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA512),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA384),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA512),
    new TestCase(EllipticCurves.getNistP521Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP521Params(), HashType.SHA512)
  };

  @Theory
  public void constructor_works(@FromDataPoints("testCases") TestCase testCase) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(testCase.paramSpec());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    byte[] message = "Hello".getBytes(UTF_8);

    EcdsaEncoding[] encodings = new EcdsaEncoding[] {EcdsaEncoding.IEEE_P1363, EcdsaEncoding.DER};
    for (EcdsaEncoding encoding : encodings) {
      // Sign with EcdsaSignJce
      EcdsaSignJce signer = new EcdsaSignJce(priv, testCase.hash(), encoding);
      byte[] signature = signer.sign(message);

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, testCase.hash(), encoding);
      verifier.verify(signature, message);
    }
  }
}
