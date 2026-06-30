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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link EcdsaVerifier}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class EcdsaVerifierTest {

  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    EcdsaPrivateKey key = (EcdsaPrivateKey) testVector.getPrivateKey();

    PublicKeyVerify verifier = EcdsaVerifier.create(key.getPublicKey());

    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> EcdsaVerifier.create(null));
  }

  @Theory
  public void verify_modifiedMessage_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    EcdsaPrivateKey key = (EcdsaPrivateKey) testVector.getPrivateKey();
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});

    PublicKeyVerify verifier = EcdsaVerifier.create(key.getPublicKey());

    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  @Theory
  public void verify_modifiedSignature_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    EcdsaPrivateKey key = (EcdsaPrivateKey) testVector.getPrivateKey();
    byte[] modifiedSignature = testVector.getSignature();
    if (modifiedSignature.length == 0) {
      return;
    }
    modifiedSignature[modifiedSignature.length - 1] ^= 0x01;

    PublicKeyVerify verifier = EcdsaVerifier.create(key.getPublicKey());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            verifier.verify(
                Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                testVector.getMessage()));
  }

  @Theory
  public void verify_modifiedSignatureOutputPrefix_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    EcdsaPrivateKey key = (EcdsaPrivateKey) testVector.getPrivateKey();
    if (key.getOutputPrefix().size() == 0) {
      return;
    }
    byte[] modifiedSignature = testVector.getSignature();
    modifiedSignature[1] ^= 0x01;

    PublicKeyVerify verifier = EcdsaVerifier.create(key.getPublicKey());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            verifier.verify(
                Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                testVector.getMessage()));
  }

  public static class WycheproofTestCase {
    private final String fileName;
    private final EcdsaParameters.SignatureEncoding encoding;

    public String fileName() {
      return fileName;
    }

    public EcdsaParameters.SignatureEncoding encoding() {
      return encoding;
    }

    public WycheproofTestCase(String fileName, EcdsaParameters.SignatureEncoding encoding) {
      this.fileName = fileName;
      this.encoding = encoding;
    }
  }

  @DataPoints("wycheproofTestCases")
  public static final WycheproofTestCase[] wycheproofTestCases =
      new WycheproofTestCase[] {
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json",
            EcdsaParameters.SignatureEncoding.DER),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_test.json",
            EcdsaParameters.SignatureEncoding.DER),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp384r1_sha512_test.json",
            EcdsaParameters.SignatureEncoding.DER),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp521r1_sha512_test.json",
            EcdsaParameters.SignatureEncoding.DER),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json",
            EcdsaParameters.SignatureEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json",
            EcdsaParameters.SignatureEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp384r1_sha512_p1363_test.json",
            EcdsaParameters.SignatureEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "third_party/wycheproof/testvectors_v1/ecdsa_secp521r1_sha512_p1363_test.json",
            EcdsaParameters.SignatureEncoding.IEEE_P1363)
      };

  private static EcdsaParameters.CurveType getCurveType(String curveName)
      throws NoSuchAlgorithmException {
    switch (curveName) {
      case "secp256r1":
        return EcdsaParameters.CurveType.NIST_P256;
      case "secp384r1":
        return EcdsaParameters.CurveType.NIST_P384;
      case "secp521r1":
        return EcdsaParameters.CurveType.NIST_P521;
      default:
        throw new NoSuchAlgorithmException("Unknown curve name: " + curveName);
    }
  }

  private static EcdsaParameters.HashType getHashType(String md) throws NoSuchAlgorithmException {
    switch (md) {
      case "SHA-256":
        return EcdsaParameters.HashType.SHA256;
      case "SHA-384":
        return EcdsaParameters.HashType.SHA384;
      case "SHA-512":
        return EcdsaParameters.HashType.SHA512;
      default:
        throw new NoSuchAlgorithmException("Unsupported hash name: " + md);
    }
  }

  @Theory
  public void testWycheproofVectors(
      @FromDataPoints("wycheproofTestCases") WycheproofTestCase testCase) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }
    JsonObject jsonObj = WycheproofTestUtil.readJson(testCase.fileName());

    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();

      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encodedPubKey = Hex.decode(group.get("publicKeyDer").getAsString());
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      ECPublicKey ecPubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
      ECPoint w = ecPubKey.getW();

      String sha = group.get("sha").getAsString();
      String curveName = group.getAsJsonObject("publicKey").get("curve").getAsString();

      EcdsaParameters parameters =
          EcdsaParameters.builder()
              .setSignatureEncoding(testCase.encoding())
              .setCurveType(getCurveType(curveName))
              .setHashType(getHashType(sha))
              .setVariant(EcdsaParameters.Variant.NO_PREFIX)
              .build();

      EcdsaPublicKey publicKey =
          EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(w).build();

      PublicKeyVerify verifier = EcdsaVerifier.create(publicKey);

      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            errors.add("FAIL " + tcId + ": accepting invalid signature");
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add(
                "FAIL " + tcId + ": rejecting valid signature, exception: " + ex.getMessage());
          }
        }
      }
    }
    assertEquals(Collections.emptyList(), errors);
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] testVectors = EcdsaTestUtil.createEcdsaTestVectors();
}
