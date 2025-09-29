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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link Ed25519Sign}. */
@RunWith(Theories.class)
public final class Ed25519SignTest {

  @Test
  public void newKeyPairSignAndVerify_works() throws Exception {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
    Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
    for (int i = 0; i < 100; i++) {
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      verifier.verify(sig, msg);
    }
  }

  @Test
  public void sign_isDeterministic() throws Exception {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
    Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
    byte[] msg = Random.randBytes(20);
    byte[] sig = signer.sign(msg);
    verifier.verify(sig, msg);

    for (int i = 0; i < 100; i++) {
      // Ed25519 is deterministic, expect a unique signature for the same message.
      assertThat(signer.sign(msg)).isEqualTo(sig);
    }
  }

  @Test
  public void privateKeyLengthDifferentFrom32Byte_throws() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Sign unused = new Ed25519Sign(new byte[31]);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Sign unused = new Ed25519Sign(new byte[33]);
        });
  }

  @Test
  public void signAndVerify_randomKeysAndMessages_works() throws Exception {
    for (int i = 0; i < 100; i++) {
      Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
      Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
      Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      verifier.verify(sig, msg);
    }
  }

  private byte[] getMessage(JsonObject testcase) throws Exception {
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void signingWithWycheproofVectors_works() throws Exception {
    JsonObject json =
        WycheproofTestUtil.readJson("testvectors/eddsa_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonObject key = group.get("key").getAsJsonObject();
      byte[] privateKey = Hex.decode(key.get("sk").getAsString());
      JsonArray tests = group.get("tests").getAsJsonArray();
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        if (result.equals("invalid")) {
          continue;
        }
        Ed25519Sign signer = new Ed25519Sign(privateKey);
        byte[] computedSig = signer.sign(msg);
        if (!Bytes.equal(sig, computedSig)) {
          errors.add(
              "FAIL " + tcId + ": got " + Hex.encode(computedSig) + ", want " + Hex.encode(sig));
        }
      }
    }
    assertThat(errors).isEmpty();
  }

  @Test
  public void keyPairFromSeedTestVector_works() throws Exception {
    byte[] secretSeed =
        Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPairFromSeed(secretSeed);
    assertThat(keyPair.getPrivateKey()).isEqualTo(secretSeed);
    assertThat(keyPair.getPublicKey())
        .isEqualTo(Hex.decode("9b62773323ef41a11834824194e55164d325eb9cdcc10ddda7d10ade4fbd8f6d"));
  }

  @Test
  public void keyPairFromSeed_seedTooShort_throws() throws Exception {
    byte[] keyMaterial = Random.randBytes(10);
    assertThrows(
        IllegalArgumentException.class, () -> Ed25519Sign.KeyPair.newKeyPairFromSeed(keyMaterial));
  }

  @Theory
  public void sign_outputsSameSignatureAsInTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();

    PublicKeySign signer = Ed25519Sign.create(key);
    byte[] signature = signer.sign(testVector.getMessage());
    // Ed25519 is deterministic, so signature must be the same as in the test vector.
    assertThat(signature).isEqualTo(testVector.getSignature());
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] testVectors =
      Ed25519TestUtil.createEd25519TestVectors();
}
