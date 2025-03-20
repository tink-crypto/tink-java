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
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPkcs1SignConscrypt RsaSsaPkcs1VerifyConscrypt. */
@RunWith(Theories.class)
public class RsaSsaPkcs1SignVerifyConscryptTest {

  @Before
  public void useConscrypt() throws Exception {
    if (!Util.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] allTests =
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors();

  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPkcs1VerifyConscrypt.create(
            (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), new byte[] {1, 2, 3}));
  }

  @Theory
  public void signWithKeysInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeySign signer =
        RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) testVector.getPrivateKey());
    byte[] signature = signer.sign(testVector.getMessage());
    // RSA-SSA-PKCS1.5 signatures are deterministic.
    assertThat(signature).isEqualTo(testVector.getSignature());
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

  @DataPoints("wycheproofTestVectorPaths")
  public static final String[] wycheproofTestVectorPaths =
      new String[] {
        "../wycheproof/testvectors/rsa_signature_2048_sha256_test.json",
        "../wycheproof/testvectors/rsa_signature_3072_sha512_test.json",
        "../wycheproof/testvectors/rsa_signature_4096_sha512_test.json"
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
        PublicKeyVerify verifier = RsaSsaPkcs1VerifyConscrypt.create(publicKey);
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
