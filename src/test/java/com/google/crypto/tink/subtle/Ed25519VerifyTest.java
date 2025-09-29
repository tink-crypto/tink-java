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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link Ed25519Verify}. */
@RunWith(Theories.class)
public final class Ed25519VerifyTest {
  @Test
  public void publicKeyLengthDifferentFrom32Byte_throws() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Verify unused = new Ed25519Verify(new byte[31]);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Verify unused = new Ed25519Verify(new byte[33]);
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
  public void verifyWithWycheproofVectors_works() throws Exception {
    JsonObject json =
        WycheproofTestUtil.readJson("testvectors/eddsa_test.json");
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
        Ed25519Verify verifier = new Ed25519Verify(publicKey);
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

  /**
   * Tests that the verifier can verify a the signature for the message and key in the test vector.
   */
  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();

      PublicKeyVerify verifier = Ed25519Verify.create(key.getPublicKey());

      verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  @Theory
  public void verify_modifiedMessage_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});

      PublicKeyVerify verifier = Ed25519Verify.create(key.getPublicKey());

      assertThrows(
          GeneralSecurityException.class,
          () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  /** Tests that verify fails if we modify the output prefix of the signature. */
  @Theory
  public void verify_modifiedSignatureOutputPrefix_throws(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      if (key.getOutputPrefix().size() == 0) {
        return;
      }
      byte[] modifiedSignature = testVector.getSignature();
      modifiedSignature[1] ^= 0x01;

      PublicKeyVerify verifier = Ed25519Verify.create(key.getPublicKey());

      assertThrows(
          GeneralSecurityException.class,
          () ->
              verifier.verify(
                  Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                  testVector.getMessage()));
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] testVectors =
      Ed25519TestUtil.createEd25519TestVectors();
}
