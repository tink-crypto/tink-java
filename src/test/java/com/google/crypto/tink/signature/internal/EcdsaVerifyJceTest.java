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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for EcdsaVerifyJce. */
@RunWith(Theories.class)
public class EcdsaVerifyJceTest {

  @BeforeClass
  public static void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test ECDSA verify in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  public static class WycheproofTestCase {
    private final String fileName;
    private final EcdsaEncoding encoding;

    public String fileName() {
      return fileName;
    }

    public EcdsaEncoding encoding() {
      return encoding;
    }

    public WycheproofTestCase(String fileName, EcdsaEncoding encoding) {
      this.fileName = fileName;
      this.encoding = encoding;
    }
  }

  @DataPoints("wycheproofTestCases")
  public static final WycheproofTestCase[] wycheproofTestCases =
      new WycheproofTestCase[] {
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json",
            EcdsaEncoding.DER),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp256r1_sha512_test.json",
            EcdsaEncoding.DER),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp384r1_sha384_test.json",
            EcdsaEncoding.DER),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp384r1_sha512_test.json",
            EcdsaEncoding.DER),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp521r1_sha512_test.json",
            EcdsaEncoding.DER),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp256r1_sha256_p1363_test.json",
            EcdsaEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp384r1_sha384_p1363_test.json",
            EcdsaEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp384r1_sha512_p1363_test.json",
            EcdsaEncoding.IEEE_P1363),
        new WycheproofTestCase(
            "../wycheproof/testvectors/ecdsa_secp521r1_sha512_p1363_test.json",
            EcdsaEncoding.IEEE_P1363)
      };

  @Theory
  public void testWycheproofVectors(
      @FromDataPoints("wycheproofTestCases") WycheproofTestCase testCase) throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(testCase.fileName());

    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();

      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encodedPubKey = Hex.decode(group.get("keyDer").getAsString());
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      String sha = group.get("sha").getAsString();
      String signatureAlgorithm = WycheproofTestUtil.getSignatureAlgorithmName(sha, "ECDSA");
      assertThat(signatureAlgorithm).isNotEmpty();
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
        HashType hash = WycheproofTestUtil.getHashType(sha);
        EcdsaVerifyJce verifier = new EcdsaVerifyJce(pubKey, hash, testCase.encoding());

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

  private static byte[] getMessage(JsonObject testcase) throws Exception {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void testConstrutorExceptions() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    // Verify with EcdsaVerifyJce.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new EcdsaVerifyJce(pub, HashType.SHA1, EcdsaEncoding.DER));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  public static class TestCase {
    private final ECParameterSpec paramSpec;
    private final HashType hash;

    public ECParameterSpec paramSpec() {
      return paramSpec;
    }

    public HashType hash() {
      return hash;
    }

    public TestCase(ECParameterSpec paramSpec, HashType hash) {
      this.paramSpec = paramSpec;
      this.hash = hash;
    }
  }

  @DataPoints("testCases")
  public static final TestCase[] testCases = {
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA384),
    new TestCase(EllipticCurves.getNistP256Params(), HashType.SHA512),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA384),
    new TestCase(EllipticCurves.getNistP384Params(), HashType.SHA512),
    new TestCase(EllipticCurves.getNistP521Params(), HashType.SHA256),
    new TestCase(EllipticCurves.getNistP521Params(), HashType.SHA512)
  };

  @Theory
  public void testAgainstJceSignatureInstance(@FromDataPoints("testCases") TestCase testCase)
      throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(testCase.paramSpec());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    byte[] message = "Hello".getBytes(UTF_8);

    // Sign with JCE's Signature.
    Signature signer = Signature.getInstance(SubtleUtil.toEcdsaAlgo(testCase.hash()));
    signer.initSign(priv);
    signer.update(message);
    byte[] signature = signer.sign();

    // Verify with EcdsaVerifyJce.
    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, testCase.hash(), EcdsaEncoding.DER);
    verifier.verify(signature, message);
  }

  @Theory
  public void testSignVerify(@FromDataPoints("testCases") TestCase testCase) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(testCase.paramSpec());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    byte[] message = "Hello".getBytes(UTF_8);

    EcdsaEncoding[] encodings = new EcdsaEncoding[] {EcdsaEncoding.IEEE_P1363, EcdsaEncoding.DER};
    for (EcdsaEncoding encoding : encodings) {
      // Sign with EcdsaSignJce
      EcdsaSignJce signer = new EcdsaSignJce(priv, testCase.hash(), encoding);
      byte[] signature = signer.sign(message);

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, testCase.hash(), encoding);
      verifier.verify(signature, message);
    }
  }

  @Test
  public void testModification() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    byte[] message = "Hello".getBytes(UTF_8);

    EcdsaEncoding[] encodings = new EcdsaEncoding[] {EcdsaEncoding.IEEE_P1363, EcdsaEncoding.DER};
    for (EcdsaEncoding encoding : encodings) {
      // Sign with EcdsaSignJce
      EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, encoding);
      byte[] signature = signer.sign(message);

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, HashType.SHA256, encoding);

      for (final BytesMutation mutation : TestUtil.generateMutations(signature)) {
        assertThrows(
            String.format(
                "Invalid signature, should have thrown exception : signature = %s, message = %s, "
                    + " description = %s",
                Hex.encode(mutation.value), Arrays.toString(message), mutation.description),
            GeneralSecurityException.class,
            () -> verifier.verify(mutation.value, message));
      }

      // Encodings mismatch.
      EcdsaVerifyJce verifier2 =
          new EcdsaVerifyJce(
              pub,
              HashType.SHA256,
              encoding == EcdsaEncoding.IEEE_P1363 ? EcdsaEncoding.DER : EcdsaEncoding.IEEE_P1363);
      assertThrows(GeneralSecurityException.class, () -> verifier2.verify(signature, message));
    }
  }

  // A ECPublicKey implementation that returns a point that is not on the curve.
  private static class InvalidEcPublicKey implements ECPublicKey {
    private final ECPublicKey validPublicKey;

    public InvalidEcPublicKey(ECPublicKey validPublicKey) {
      this.validPublicKey = validPublicKey;
    }

    @Override
    public String getAlgorithm() {
      return validPublicKey.getAlgorithm();
    }

    @Override
    public byte[] getEncoded() {
      return validPublicKey.getEncoded();
    }

    @Override
    public String getFormat() {
      return validPublicKey.getFormat();
    }

    @Override
    public ECPoint getW() {
      ECPoint w = validPublicKey.getW();
      BigInteger invalidY = w.getAffineY().add(BigInteger.ONE);
      return new ECPoint(w.getAffineX(), invalidY);
    }

    @Override
    public ECParameterSpec getParams() {
      return validPublicKey.getParams();
    }
  }

  @Test
  public void testInvalidPublicKey() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EllipticCurves.getNistP256Params());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey validPublicKey = (ECPublicKey) keyPair.getPublic();
    ECPublicKey invalidPublicKey = new InvalidEcPublicKey(validPublicKey);

    assertThrows(
        GeneralSecurityException.class,
        () -> new EcdsaVerifyJce(invalidPublicKey, HashType.SHA256, EcdsaEncoding.DER));
  }
}
