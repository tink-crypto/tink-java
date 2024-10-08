// Copyright 2024 Google LLC
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

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Ed25519VerifyJceTest}. */
@RunWith(JUnit4.class)
public final class Ed25519VerifyJceTest {

  @Test
  public void x509EncodePublicKey_works() throws Exception {
    // Use public key from https://datatracker.ietf.org/doc/html/rfc8410#section-10.1.
    byte[] publicKey =
        Hex.decode("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
    byte[] encoded = Ed25519VerifyJce.x509EncodePublicKey(publicKey);
    assertThat(Base64.encodeToString(encoded, Base64.DEFAULT | Base64.NO_WRAP))
        .isEqualTo("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=");
  }

  @Test
  public void x509EncodePublicKey_withInvalidKeyLength_throws() throws Exception {
    byte[] publicKeyWithLeadingZero =
        Hex.decode("0019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
    assertThrows(
        IllegalArgumentException.class,
        () -> Ed25519VerifyJce.x509EncodePublicKey(publicKeyWithLeadingZero));
  }

  boolean isJavaOneDotEight() {
    return System.getProperty("java.version").startsWith("1.8");
  }

  @Test
  public void isSupported_returnsTrueExceptForJavaOneDotEight() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && !Util.isAndroid());

    if (isJavaOneDotEight()) {
      assertThat(Ed25519VerifyJce.isSupported()).isFalse();
    } else {
      assertThat(Ed25519VerifyJce.isSupported()).isTrue();
    }
  }

  @Test
  public void isSupported_onAndroid_returnsFalse() throws Exception {
    Assume.assumeTrue(Util.isAndroid());

    assertThat(Ed25519VerifyJce.isSupported()).isFalse();
  }

  @Test
  public void testVerificationWithPublicKeyLengthDifferentFrom32Byte() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519VerifyJce.isSupported());
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519VerifyJce unused = new Ed25519VerifyJce(new byte[31]);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519VerifyJce unused = new Ed25519VerifyJce(new byte[33]);
        });
  }

  private byte[] getMessage(JsonObject testcase) throws Exception {
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void testVerificationWithWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519VerifyJce.isSupported());

    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/eddsa_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonObject key = group.get("key").getAsJsonObject();
      byte[] publicKey = Hex.decode(key.get("pk").getAsString());
      JsonArray tests = group.get("tests").getAsJsonArray();
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        Ed25519VerifyJce verifier = new Ed25519VerifyJce(publicKey);
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
    assertThat(errors).isEmpty();
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    assertThrows(RuntimeException.class, () -> new Ed25519VerifyJce(new byte[32]));
  }

  /**
   * Tests that the verifier can verify a the signature for the message and key in the test vector.
   */
  @Test
  public void test_validateSignatureInTestVector() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519VerifyJce.isSupported());
    // We are not using parameterized tests because the next line cannot be run if useOnlyFips.
    SignatureTestVector[] testVectors = Ed25519TestUtil.createEd25519TestVectors();
    for (SignatureTestVector testVector : testVectors) {

      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      PublicKeyVerify verifier = Ed25519VerifyJce.create(key.getPublicKey());
      verifier.verify(testVector.getSignature(), testVector.getMessage());
    }
  }

  @Test
  public void test_computeAndValidate_modifiedMessage_throws() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519VerifyJce.isSupported());
    // We are not using parameterized tests because the next line cannot be run if useOnlyFips.
    SignatureTestVector[] testVectors = Ed25519TestUtil.createEd25519TestVectors();
    for (SignatureTestVector testVector : testVectors) {
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});
      PublicKeyVerify verifier = Ed25519VerifyJce.create(key.getPublicKey());
      assertThrows(
          GeneralSecurityException.class,
          () -> verifier.verify(testVector.getSignature(), modifiedMessage));
    }
  }

  /** Tests that the verification fails if we modify the output prefix. */
  @Test
  public void test_computeAndValidate_modifiedOutputPrefix_throws() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519VerifyJce.isSupported());
    // We are not using parameterized tests because the next line cannot be run if useOnlyFips.
    SignatureTestVector[] testVectors = Ed25519TestUtil.createEd25519TestVectors();
    for (SignatureTestVector testVector : testVectors) {
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      if (key.getOutputPrefix().size() == 0) {
        return;
      }
      byte[] modifiedSignature = testVector.getSignature();
      modifiedSignature[1] ^= 0x01;
      PublicKeyVerify verifier = Ed25519VerifyJce.create(key.getPublicKey());
      assertThrows(
          GeneralSecurityException.class,
          () ->
              verifier.verify(
                  Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                  testVector.getMessage()));
    }
  }
}
