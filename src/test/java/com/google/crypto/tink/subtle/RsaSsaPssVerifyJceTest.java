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
import com.google.crypto.tink.internal.Util;
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
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
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

/** Unit tests for RsaSsaPssVerifyJce. */
@RunWith(Theories.class)
public class RsaSsaPssVerifyJceTest {

  @DataPoints("testVectors")
  public static final SignatureTestVector[] testVectors =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Theory
  public void verifySignatureInTestVector_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verifier =
        RsaSsaPssVerifyJce.create((RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());

    // Test that verify fails when message is modified.
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  private static HashType toEnumHashType(RsaSsaPssParameters.HashType hash) {
    if (hash == RsaSsaPssParameters.HashType.SHA256) {
      return HashType.SHA256;
    } else if (hash == RsaSsaPssParameters.HashType.SHA384) {
      return HashType.SHA384;
    } else if (hash == RsaSsaPssParameters.HashType.SHA512) {
      return HashType.SHA512;
    } else {
      throw new IllegalArgumentException("Unsupported hash: " + hash);
    }
  }

  @Theory
  public void constructor_verifySignatureInTestVector_works(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPublicKey testPublicKey =
        (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();
    if (!testPublicKey.getParameters().getVariant().equals(RsaSsaPssParameters.Variant.NO_PREFIX)) {
      // Constructor doesn't support output prefix.
      return;
    }
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey rsaPublicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));

    RsaSsaPssVerifyJce verify =
        new RsaSsaPssVerifyJce(
            rsaPublicKey,
            toEnumHashType(testPublicKey.getParameters().getSigHashType()),
            toEnumHashType(testPublicKey.getParameters().getMgf1HashType()),
            testPublicKey.getParameters().getSaltLengthBytes());
    verify.verify(testVector.getSignature(), testVector.getMessage());

    // Test that verify fails when message is modified.
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});
    assertThrows(
        GeneralSecurityException.class,
        () -> verify.verify(testVector.getSignature(), modifiedMessage));
  }

  @Test
  public void constructorValidatesHashType() throws Exception {
    SignatureTestVector testVector = testVectors[0];
    RsaSsaPssPublicKey testPublicKey =
        (RsaSsaPssPublicKey) testVector.getPrivateKey().getPublicKey();
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey rsaPublicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));

    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssVerifyJce(rsaPublicKey, HashType.SHA1, HashType.SHA1, 20));
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssVerifyJce(rsaPublicKey, HashType.SHA256, HashType.SHA1, 32));
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssVerifyJce(rsaPublicKey, HashType.SHA256, HashType.SHA384, 32));
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
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(testPublicKey);
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
  public static final String[] WYCHEPROOF_TEST_VECTORS_PATHS =
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
        PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(publicKey);
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

    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(testPublicKey);
    assertThat(verifier.getClass().getSimpleName()).isEqualTo("InternalImpl");

    Provider conscrypt = Conscrypt.newProvider();
    Security.addProvider(conscrypt);

    PublicKeyVerify verifier2 = RsaSsaPssVerifyJce.create(testPublicKey);
    assertThat(verifier2.getClass().getSimpleName()).isEqualTo("RsaSsaPssVerifyConscrypt");

    Security.removeProvider(conscrypt.getName());
  }

  @Test
  public void verify_maxSaltLengthWithModulusBitLengthMod8Equals2_works() throws Exception {
    // 2050-bit RSA modulus (bitLength % 8 == 2 => emBits = 2049, emLen = 257, 8*emLen - emBits = 7)
    // with maximum salt length for SHA-256 (emLen - hLen - 2 = 257 - 32 - 2 = 223), so that the
    // 0x01 separator in DB is at db[0].
    BigInteger modulus =
        new BigInteger(
            1,
            Hex.decode(
                "034db288b4f23f071010e1e9537cb84a2ae5a3dbb858241ba3510d7c5d4433933efb24aa6532e61297"
                    + "61556374aa46dad2a9195c64c77899388808bfb8e1bf7fa1a896cc15738d1e1eb1c8dd95d7d5"
                    + "6b7a6c8edd1136cd16cdbf0403147f4b6c045608edc5b43429a6023c57b70563fc2230045dbd"
                    + "a6219462f5ff46701cd7747b52d105900128f4fc50aa623f9a64bc15b70720932161e9bd6fde"
                    + "d2f9ae3dff38255ee3dfc081e9750036e81e6cd62b6df3919fe6b20d6c2838e38f9e10b212d5"
                    + "77ecc22f7fdaddedafc36dfd3f479ac6301c1f3a42b8ee9301e84c4273262672ca7aa07f3f33"
                    + "d2665f4ff3dc11b90a1e6ca69e8dd36470fdcaed08e6d5d51661"));
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2050)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(223)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(modulus).build();
    byte[] message = Hex.decode("aa");
    byte[] signature =
        Hex.decode(
            "01d8971bb548b3a417c5224fed63af53d8c6f480771c73f37b9191671a8a29e76b6134402ab9dd083c75f1"
                + "2f81583f9b5c92d2cb1ea0ca59d4dda310d6e8beb560843a9122f84ea20c0f28b2665a40e951bf88"
                + "b0156edaf07a787dcc750e25ff17c0748cd3f250c0d37b7265753edf0849d365b6e7674009a9c2c2"
                + "015cbeaab27aea3a22d5c418fc66c3b90a32cef362c9b2da34a329423909b261eb76386777940864"
                + "98b2473bd6f823c42f6fcf270acfaa8b09e13c0d0b5f0782873e1d16ffefaabfd6beca518e01bffe"
                + "7fc3b84b0f825b4f87c997b0ab664aa285d3a298f9f238f9ea486d966d66c1fab85acd991e87398b"
                + "7d5d63e50e31c72d124f8d7c1b0f");

    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(publicKey);
    verifier.verify(signature, message);

    byte[] modifiedMessage = Bytes.concat(message, new byte[] {1});
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> verifier.verify(signature, modifiedMessage));
    if (Util.isAndroid()) {
      assertThat(e).hasMessageThat().isEqualTo("signature verification failed");
    } else {
      assertThat(e).hasMessageThat().isEqualTo("inconsistent");
    }
  }
}
