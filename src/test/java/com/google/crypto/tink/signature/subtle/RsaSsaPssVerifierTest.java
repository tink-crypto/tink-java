// Copyright 2026 Google LLC
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

package com.google.crypto.tink.signature.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link RsaSsaPssVerifier}. */
@RunWith(Theories.class)
public class RsaSsaPssVerifierTest {

  @DataPoints("testVectors")
  public static final SignatureTestVector[] testVectors =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPssVerifier.create((RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());

    // Test that verify fails when message is modified.
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  @Theory
  public void modifiedOutputPrefix_throws(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPublicKey testPublicKey =
        (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();
    if (testPublicKey.getOutputPrefix().size() == 0) {
      return;
    }
    byte[] modifiedSignature = testVector.getSignature();
    modifiedSignature[1] ^= 0x01;
    PublicKeyVerify verifier = RsaSsaPssVerifier.create(testPublicKey);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            verifier.verify(
                Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                testVector.getMessage()));
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
  public static final String[] wycheproofTestVectorPaths =
      new String[] {
        "third_party/wycheproof/testvectors_v1/rsa_pss_2048_sha256_mgf1_0_test.json",
        "third_party/wycheproof/testvectors_v1/rsa_pss_2048_sha256_mgf1_32_test.json",
        "third_party/wycheproof/testvectors_v1/rsa_pss_3072_sha256_mgf1_32_test.json",
        "third_party/wycheproof/testvectors_v1/rsa_pss_4096_sha256_mgf1_32_test.json",
        "third_party/wycheproof/testvectors_v1/rsa_pss_4096_sha512_mgf1_32_test.json"
      };

  @Theory
  public void wycheproofVectors(@FromDataPoints("wycheproofTestVectorPaths") String path)
      throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(path);

    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonObject publicKeyData = group.get("publicKey").getAsJsonObject();
      BigInteger modulus = new BigInteger(publicKeyData.get("modulus").getAsString(), 16);
      BigInteger exponent = new BigInteger(publicKeyData.get("publicExponent").getAsString(), 16);
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
        PublicKeyVerify verifier = RsaSsaPssVerifier.create(publicKey);
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            errors.add("FAIL " + tcId + ": accepting invalid signature");
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + ": rejecting valid signature, exception: " + ex);
          }
        }
      }
    }
    assertThat(errors).isEmpty();
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
  public void usesConscryptImplementationIfInstalled() throws Exception {
    Assume.assumeFalse(Util.isAndroid());
    Assume.assumeTrue(Conscrypt.isAvailable());

    SignatureTestVector testVector = testVectors[0];
    RsaSsaPssPublicKey testPublicKey =
        (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();

    PublicKeyVerify verifier = RsaSsaPssVerifier.create(testPublicKey);
    assertThat(verifier.getClass().getSimpleName()).isEqualTo("InternalImpl");

    Provider conscrypt = Conscrypt.newProvider();
    Security.addProvider(conscrypt);

    PublicKeyVerify verifier2 = RsaSsaPssVerifier.create(testPublicKey);
    assertThat(verifier2.getClass().getSimpleName()).isEqualTo("RsaSsaPssVerifyConscrypt");

    Security.removeProvider(conscrypt.getName());
  }
}
