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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssVerifyJce. */
@RunWith(Theories.class)
public class RsaSsaPssVerifyJceTest {

  @DataPoints("testVectors")
  public static final SignatureTestVector[] TEST_VECTORS =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPssVerifyJce.create((RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), new byte[] {1, 2, 3}));
  }

  @Test
  public void constructorWorks() throws Exception {
    SignatureTestVector testVector = TEST_VECTORS[0];
    RsaSsaPssPublicKey testPublicKey =
        (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();
    assertThat(testPublicKey.getParameters().getSigHashType())
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);
    assertThat(testPublicKey.getParameters().getMgf1HashType())
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey rsaPublicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));

    RsaSsaPssVerifyJce verify =
        new RsaSsaPssVerifyJce(
            rsaPublicKey,
            HashType.SHA256,
            HashType.SHA256,
            testPublicKey.getParameters().getSaltLengthBytes());
    verify.verify(testVector.getSignature(), testVector.getMessage());
    assertThrows(
        GeneralSecurityException.class,
        () -> verify.verify(testVector.getSignature(), new byte[] {1, 2, 3}));

    // Test that the constructor fails when SHA1 is used.
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssVerifyJce(rsaPublicKey, HashType.SHA1, HashType.SHA1, 20));
  }

  private static RsaSsaPssParameters.HashType getHashType(String sha) {
    switch (sha) {
      case "SHA-256":
        return RsaSsaPssParameters.HashType.SHA256;
      case "SHA-512":
        return RsaSsaPssParameters.HashType.SHA512;
      default:
        throw new IllegalArgumentException("Unsupported hash: " + sha);
    }
  }

  @DataPoints("wycheproofTestVectorPaths")
  public static final String[] WYCHEPROOF_TEST_VECTORS_PATHS =
      new String[] {
        "../wycheproof/testvectors/rsa_pss_2048_sha256_mgf1_0_test.json",
        "../wycheproof/testvectors/rsa_pss_2048_sha256_mgf1_32_test.json",
        "../wycheproof/testvectors/rsa_pss_3072_sha256_mgf1_32_test.json",
        "../wycheproof/testvectors/rsa_pss_4096_sha256_mgf1_32_test.json",
        "../wycheproof/testvectors/rsa_pss_4096_sha512_mgf1_32_test.json"
      };

  @Theory
  public void wycheproofVectors(@FromDataPoints("wycheproofTestVectorPaths") String path)
      throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(path);

    int errors = 0;
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      BigInteger modulus = new BigInteger(group.get("n").getAsString(), 16);
      BigInteger exponent = new BigInteger(group.get("e").getAsString(), 16);
      RsaSsaPssParameters.HashType hashType = getHashType(group.get("sha").getAsString());
      RsaSsaPssParameters.HashType mgf1HashType = getHashType(group.get("mgfSha").getAsString());
      int saltLength = group.get("sLen").getAsInt();

      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        RsaSsaPssParameters parameters =
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(modulus.bitLength())
                .setPublicExponent(exponent)
                .setSigHashType(hashType)
                .setMgf1HashType(mgf1HashType)
                .setSaltLengthBytes(saltLength)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build();
        RsaSsaPssPublicKey publicKey =
            RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(modulus).build();
        PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(publicKey);
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
    assertThat(errors).isEqualTo(0);
  }

  private static byte[] getMessage(JsonObject testcase) {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }
}
