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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPkcs1VerifyJce. */
@RunWith(JUnit4.class)
public class RsaSsaPkcs1VerifyJceTest {

  private byte[] testMessage;
  private byte[] testSignature;
  private RsaSsaPkcs1PublicKey testPublicKey;

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test RSA PKCS1.5 verify in FIPS-mode without Conscrypt Provider", cause);
      }
    }
    SignatureTestVector testVector = RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0];
    testMessage = testVector.getMessage();
    testSignature = testVector.getSignature();
    testPublicKey = (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey();
  }

  @Test
  public void createWorks() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    PublicKeyVerify verify = RsaSsaPkcs1VerifyJce.create(testPublicKey);
    verify.verify(testSignature, testMessage);
    assertThrows(
        GeneralSecurityException.class, () -> verify.verify(testSignature, new byte[] {1, 2, 3}));
  }

  @Test
  public void constructorWorks() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));
    assertThat(testPublicKey.getParameters().getHashType())
        .isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA256);
    RsaSsaPkcs1VerifyJce verify = new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA256);
    verify.verify(testSignature, testMessage);
    assertThrows(
        GeneralSecurityException.class, () -> verify.verify(testSignature, new byte[] {1, 2, 3}));
  }

  @Test
  public void sha1IsNotSupported() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));
    assertThrows(
        GeneralSecurityException.class, () -> new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA1));
  }

  @Test
  public void constructorWithSmallExponent_throws() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(testPublicKey.getModulus(), BigInteger.valueOf(3)));
    assertThrows(
        GeneralSecurityException.class, () -> new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA256));
  }

  private static RsaSsaPkcs1Parameters.HashType getHashType(String sha) {
    switch (sha) {
      case "SHA-256":
        return RsaSsaPkcs1Parameters.HashType.SHA256;
      case "SHA-512":
        return RsaSsaPkcs1Parameters.HashType.SHA512;
      default:
        throw new IllegalArgumentException("Unsupported hash: " + sha);
    }
  }

  private static void testWycheproofVectors(String fileName) throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(fileName);

    int errors = 0;
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      BigInteger modulus = new BigInteger(group.get("n").getAsString(), 16);
      BigInteger exponent = new BigInteger(1, Hex.decode(group.get("e").getAsString()));
      RsaSsaPkcs1Parameters.HashType hashType = getHashType(group.get("sha").getAsString());
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        // Do not perform the Wycheproof test if the RSA public exponent is small.
        if (WycheproofTestUtil.checkFlags(testcase, "SmallPublicKey")) {
          continue;
        }
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        RsaSsaPkcs1Parameters parameters =
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(modulus.bitLength())
                .setPublicExponent(exponent)
                .setHashType(hashType)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build();
        RsaSsaPkcs1PublicKey publicKey =
            RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(modulus).build();
        PublicKeyVerify verifier = RsaSsaPkcs1VerifyJce.create(publicKey);
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            System.out.printf("FAIL %s: accepting invalid signature%n", tcId);
            errors++;
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: rejecting valid signature, exception: %s%n", tcId, ex);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_2048_sha256_test.json");
    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_4096_sha512_test.json");
  }

  @Test
  public void testWycheproofVectors3072() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_3072_sha512_test.json");
  }

  private static byte[] getMessage(JsonObject testcase) {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            testWycheproofVectors(
                "../wycheproof/testvectors/rsa_signature_3072_sha512_test.json"));
  }
}
