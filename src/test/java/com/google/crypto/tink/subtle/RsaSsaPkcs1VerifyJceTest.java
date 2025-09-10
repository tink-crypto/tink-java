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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.Util;
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
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPkcs1VerifyJce. */
@RunWith(Theories.class)
public class RsaSsaPkcs1VerifyJceTest {

  @DataPoints("allTests")
  public static final SignatureTestVector[] allTestVectors =
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors();

  private static HashType getSubtleHashType(RsaSsaPkcs1Parameters.HashType hash)
      throws GeneralSecurityException {
    if (hash == RsaSsaPkcs1Parameters.HashType.SHA256) {
      return HashType.SHA256;
    } else if (hash == RsaSsaPkcs1Parameters.HashType.SHA384) {
      return HashType.SHA384;
    } else if (hash == RsaSsaPkcs1Parameters.HashType.SHA512) {
      return HashType.SHA512;
    } else {
      throw new GeneralSecurityException("Unsupported hash: " + hash);
    }
  }

  @BeforeClass
  public static void useConscrypt() throws Exception {
    if (!Util.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Theory
  public void create_verifySignatureInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    PublicKeyVerify verify =
        RsaSsaPkcs1VerifyJce.create(
            (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey());
    verify.verify(testVector.getSignature(), testVector.getMessage());
    assertThrows(
        GeneralSecurityException.class,
        () -> verify.verify(testVector.getSignature(), new byte[] {1, 2, 3}));
  }

  @AccessesPartialKey
  @Theory
  public void constructor_verifySignatureInTestVector_works(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    RsaSsaPkcs1PublicKey testPublicKey =
        (RsaSsaPkcs1PublicKey) testVector.getPrivateKey().getPublicKey();
    if (testPublicKey.getParameters().getVariant() != RsaSsaPkcs1Parameters.Variant.NO_PREFIX) {
      // Constructor only supports NO_PREFIX variant.
      return;
    }
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    testPublicKey.getModulus(), testPublicKey.getParameters().getPublicExponent()));
    RsaSsaPkcs1VerifyJce verify =
        new RsaSsaPkcs1VerifyJce(
            publicKey, getSubtleHashType(testPublicKey.getParameters().getHashType()));
    verify.verify(testVector.getSignature(), testVector.getMessage());
    assertThrows(
        GeneralSecurityException.class,
        () -> verify.verify(testVector.getSignature(), new byte[] {1, 2, 3}));
  }

  @Test
  public void sha1IsNotSupported() throws Exception {
    RsaSsaPkcs1PublicKey testPublicKey =
        (RsaSsaPkcs1PublicKey) allTestVectors[0].getPrivateKey().getPublicKey();
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
    RsaSsaPkcs1PublicKey testPublicKey =
        (RsaSsaPkcs1PublicKey) allTestVectors[0].getPrivateKey().getPublicKey();
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
      case "SHA-384":
        return RsaSsaPkcs1Parameters.HashType.SHA384;
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
        "../wycheproof/testvectors/rsa_signature_2048_sha384_test.json",
        "../wycheproof/testvectors/rsa_signature_2048_sha512_test.json",
        "../wycheproof/testvectors/rsa_signature_3072_sha256_test.json",
        "../wycheproof/testvectors/rsa_signature_3072_sha384_test.json",
        "../wycheproof/testvectors/rsa_signature_3072_sha512_test.json",
        "../wycheproof/testvectors/rsa_signature_4096_sha384_test.json",
        "../wycheproof/testvectors/rsa_signature_4096_sha512_test.json"
      };

  @AccessesPartialKey
  @Theory
  public void wycheproofVectors(@FromDataPoints("wycheproofTestVectorPaths") String path)
      throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(path);

    ArrayList<String> errors = new ArrayList<>();
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

    RsaSsaPkcs1PublicKey testPublicKey =
        (RsaSsaPkcs1PublicKey) allTestVectors[0].getPrivateKey().getPublicKey();

    // Conscrypt is already installed, so RsaSsaPkcs1VerifyConscrypt is used.
    PublicKeyVerify verifier = RsaSsaPkcs1VerifyJce.create(testPublicKey);
    assertThat(verifier.getClass().getSimpleName()).isEqualTo("RsaSsaPkcs1VerifyConscrypt");

    Provider conscrypt = Conscrypt.newProvider();
    Security.removeProvider(conscrypt.getName());

    PublicKeyVerify verifier2 = RsaSsaPkcs1VerifyJce.create(testPublicKey);
    assertThat(verifier2.getClass().getSimpleName()).isEqualTo("InternalJavaImpl");

    Security.addProvider(conscrypt);
  }
}
