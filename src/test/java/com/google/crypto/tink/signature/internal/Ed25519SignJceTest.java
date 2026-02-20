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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.TreeSet;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Ed25519SignJce}. */
@RunWith(JUnit4.class)
public final class Ed25519SignJceTest {

  @BeforeClass
  public static void useConscrypt() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void pkcs8EncodePrivateKey_works() throws Exception {
    // Use private key from https://datatracker.ietf.org/doc/html/rfc8410#section-10.3.
    byte[] privateKey =
        Hex.decode("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
    byte[] encoded = Ed25519SignJce.pkcs8EncodePrivateKey(privateKey);
    assertThat(Base64.encodeToString(encoded, Base64.DEFAULT | Base64.NO_WRAP))
        .isEqualTo("MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");
  }

  @Test
  public void pkcs8EncodePrivateKey_withInvalidKeyLength_throws() throws Exception {
    byte[] privateKeyWithLeadingZero =
        Hex.decode("00D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
    assertThrows(
        IllegalArgumentException.class,
        () -> Ed25519SignJce.pkcs8EncodePrivateKey(privateKeyWithLeadingZero));
  }

  @Test
  public void isSupported_notOnAndroid_doesNotThrow() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && !Util.isAndroid());

    // We still test with Conscrypt versions that don't support Ed25519.
    // So we can't assert that it is true.
    boolean unused = Ed25519SignJce.isSupported();
  }

  @Test
  public void isSupported_onAndroid_returnsFalse() throws Exception {
    Assume.assumeTrue(Util.isAndroid());

    assertThat(Ed25519SignJce.isSupported()).isFalse();
  }

  @Test
  public void testSigningOneKeyWithMultipleMessages() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());

    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519SignJce signer = new Ed25519SignJce(keyPair.getPrivateKey());
    Ed25519VerifyJce verifier = new Ed25519VerifyJce(keyPair.getPublicKey());
    for (int i = 0; i < 100; i++) {
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        throw new AssertionError(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                Hex.encode(msg),
                Hex.encode(sig),
                Hex.encode(keyPair.getPrivateKey()),
                Hex.encode(keyPair.getPublicKey())),
            ex);
      }
    }
  }

  @Test
  public void testSigningOneKeyWithTheSameMessage() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());

    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519SignJce signer = new Ed25519SignJce(keyPair.getPrivateKey());
    Ed25519VerifyJce verifier = new Ed25519VerifyJce(keyPair.getPublicKey());
    byte[] msg = Random.randBytes(20);
    TreeSet<String> allSignatures = new TreeSet<String>();
    for (int i = 0; i < 100; i++) {
      byte[] sig = signer.sign(msg);
      allSignatures.add(Hex.encode(sig));
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        throw new AssertionError(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                Hex.encode(msg),
                Hex.encode(sig),
                Hex.encode(keyPair.getPrivateKey()),
                Hex.encode(keyPair.getPublicKey())),
            ex);
      }
    }
    // Ed25519 is deterministic, expect a unique signature for the same message.
    assertEquals(1, allSignatures.size());
  }

  @Test
  public void testSignWithPrivateKeyLengthDifferentFrom32Byte() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519SignJce unused = new Ed25519SignJce(new byte[31]);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519SignJce unused = new Ed25519SignJce(new byte[33]);
        });
  }

  @Test
  public void testSigningWithMultipleRandomKeysAndMessages() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());

    for (int i = 0; i < 100; i++) {
      Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
      Ed25519SignJce signer = new Ed25519SignJce(keyPair.getPrivateKey());
      Ed25519VerifyJce verifier = new Ed25519VerifyJce(keyPair.getPublicKey());
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        throw new AssertionError(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                Hex.encode(msg),
                Hex.encode(sig),
                Hex.encode(keyPair.getPrivateKey()),
                Hex.encode(keyPair.getPublicKey())),
            ex);
      }
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
  public void testSigningWithWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors/eddsa_test.json");
    int errors = 0;
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
        Ed25519SignJce signer = new Ed25519SignJce(privateKey);
        byte[] computedSig = signer.sign(msg);
        assertArrayEquals(tcId, sig, computedSig);
      }
    }
    assertEquals(0, errors);
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(32);
    assertThrows(GeneralSecurityException.class, () -> new Ed25519SignJce(key));
  }

  @Test
  public void create_signAndVerifyWorksWithTestVector() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() && Ed25519SignJce.isSupported());
    // We are not using parameterized tests because the next line cannot be run if useOnlyFips.
    for (SignatureTestVector testVector : testVectors) {
      System.out.println(
          "Testing test_computeAndValidateFreshSignatureWithTestVector with parameters: "
              + testVector.getPrivateKey().getParameters());
      Ed25519PrivateKey key = (Ed25519PrivateKey) testVector.getPrivateKey();
      PublicKeySign signer = Ed25519SignJce.create(key);
      byte[] signature = signer.sign(testVector.getMessage());
      PublicKeyVerify verifier = Ed25519VerifyJce.create(key.getPublicKey());
      verifier.verify(signature, testVector.getMessage());
    }
  }

  @Test
  public void createWithProvider_nullProvider_throws() throws Exception {
    SignatureTestVector testVector = testVectors[0];
    assertThrows(
        IllegalArgumentException.class,
        () -> Ed25519SignJce.createWithProvider((Ed25519PrivateKey) testVector.getPrivateKey(), null));
  }

  @Test
  public void createWithProvider_worksWithConscryptIfSupported() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips());
    Provider conscryptProvider = ConscryptUtil.providerOrNull();
    if (conscryptProvider == null) {
      return;
    }
    SignatureTestVector testVector = testVectors[0];
    Ed25519PrivateKey privateKey = (Ed25519PrivateKey) testVector.getPrivateKey();

    PublicKeySign signer;
    try {
      signer = Ed25519SignJce.createWithProvider(privateKey, conscryptProvider);
    } catch (GeneralSecurityException e) {
      // Version of Conscrypt that doesn't yet support Ed25519.
      return;
    }

    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        Ed25519VerifyJce.createWithProvider(privateKey.getPublicKey(), conscryptProvider);
    verifier.verify(signature, testVector.getMessage());
  }

  public static final SignatureTestVector[] testVectors = Ed25519TestUtil.createEd25519TestVectors();
}
