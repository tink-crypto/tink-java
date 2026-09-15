// Copyright 2025 Google LLC
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
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class MlDsaSignerTest {

  private static final int MLDSA44_SIGNATURE_BYTES = 2420;
  private static final int MLDSA65_SIGNATURE_BYTES = 3309;
  private static final int MLDSA87_SIGNATURE_BYTES = 4627;

  private static final MlDsaParameters NO_PREFIX_MLDSA44_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.NO_PREFIX);
  private static final MlDsaParameters NO_PREFIX_MLDSA65_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);
  private static final MlDsaParameters NO_PREFIX_MLDSA87_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.NO_PREFIX);
  private static final MlDsaParameters TINK_MLDSA44_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_44, MlDsaParameters.Variant.TINK);
  private static final MlDsaParameters TINK_MLDSA65_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK);
  private static final MlDsaParameters TINK_MLDSA87_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_87, MlDsaParameters.Variant.TINK);

  private static final byte[] testData = "this is some data to be signed".getBytes(UTF_8);

  private static byte[] messageMlDsa44;
  private static byte[] noPrefixSignatureMlDsa44;
  private static byte[] tinkSignatureMlDsa44;
  private static MlDsaPublicKey noPrefixMlDsa44PublicKey;
  private static MlDsaPrivateKey noPrefixMlDsa44PrivateKey;
  private static MlDsaPublicKey tinkMlDsa44PublicKey;
  private static MlDsaPrivateKey tinkMlDsa44PrivateKey;

  private static byte[] messageMlDsa65;
  private static byte[] noPrefixSignatureMlDsa65;
  private static byte[] tinkSignatureMlDsa65;
  private static MlDsaPublicKey noPrefixMlDsa65PublicKey;
  private static MlDsaPrivateKey noPrefixMlDsa65PrivateKey;
  private static MlDsaPublicKey tinkMlDsa65PublicKey;
  private static MlDsaPrivateKey tinkMlDsa65PrivateKey;

  private static byte[] messageMlDsa87;
  private static byte[] noPrefixSignatureMlDsa87;
  private static byte[] tinkSignatureMlDsa87;
  private static MlDsaPublicKey noPrefixMlDsa87PublicKey;
  private static MlDsaPrivateKey noPrefixMlDsa87PrivateKey;
  private static MlDsaPublicKey tinkMlDsa87PublicKey;
  private static MlDsaPrivateKey tinkMlDsa87PrivateKey;

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }

    SignatureTestVector noPrefixTestVector44 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(NO_PREFIX_MLDSA44_PARAMS);
    SignatureTestVector tinkTestVector44 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(TINK_MLDSA44_PARAMS);

    noPrefixMlDsa44PrivateKey = (MlDsaPrivateKey) noPrefixTestVector44.getPrivateKey();
    noPrefixMlDsa44PublicKey = noPrefixMlDsa44PrivateKey.getPublicKey();
    noPrefixSignatureMlDsa44 = noPrefixTestVector44.getSignature();
    messageMlDsa44 = noPrefixTestVector44.getMessage();

    tinkMlDsa44PrivateKey = (MlDsaPrivateKey) tinkTestVector44.getPrivateKey();
    tinkMlDsa44PublicKey = tinkMlDsa44PrivateKey.getPublicKey();
    tinkSignatureMlDsa44 = tinkTestVector44.getSignature();

    SignatureTestVector noPrefixTestVector65 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(NO_PREFIX_MLDSA65_PARAMS);
    SignatureTestVector tinkTestVector65 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(TINK_MLDSA65_PARAMS);

    noPrefixMlDsa65PrivateKey = (MlDsaPrivateKey) noPrefixTestVector65.getPrivateKey();
    noPrefixMlDsa65PublicKey = noPrefixMlDsa65PrivateKey.getPublicKey();
    noPrefixSignatureMlDsa65 = noPrefixTestVector65.getSignature();
    messageMlDsa65 = noPrefixTestVector65.getMessage();

    tinkMlDsa65PrivateKey = (MlDsaPrivateKey) tinkTestVector65.getPrivateKey();
    tinkMlDsa65PublicKey = tinkMlDsa65PrivateKey.getPublicKey();
    tinkSignatureMlDsa65 = tinkTestVector65.getSignature();

    SignatureTestVector noPrefixTestVector87 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(NO_PREFIX_MLDSA87_PARAMS);
    SignatureTestVector tinkTestVector87 =
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(TINK_MLDSA87_PARAMS);

    noPrefixMlDsa87PrivateKey = (MlDsaPrivateKey) noPrefixTestVector87.getPrivateKey();
    noPrefixMlDsa87PublicKey = noPrefixMlDsa87PrivateKey.getPublicKey();
    noPrefixSignatureMlDsa87 = noPrefixTestVector87.getSignature();
    messageMlDsa87 = noPrefixTestVector87.getMessage();

    tinkMlDsa87PrivateKey = (MlDsaPrivateKey) tinkTestVector87.getPrivateKey();
    tinkMlDsa87PublicKey = tinkMlDsa87PrivateKey.getPublicKey();
    tinkSignatureMlDsa87 = tinkTestVector87.getSignature();
  }

  @Test
  public void signAndVerify_noPrefix_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa44PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa44PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(MLDSA44_SIGNATURE_BYTES);
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_tinkPrefix_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa44PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa44PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(5 + MLDSA44_SIGNATURE_BYTES);
    assertThat(Hex.encode(Arrays.copyOf(signature, 1))).isEqualTo("01");
    assertThat(Hex.encode(Arrays.copyOfRange(signature, 1, 5))).isEqualTo("12345678");
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_noPrefix_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa65PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa65PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(MLDSA65_SIGNATURE_BYTES);
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_tinkPrefix_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa65PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa65PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(5 + MLDSA65_SIGNATURE_BYTES);
    assertThat(Hex.encode(Arrays.copyOf(signature, 1))).isEqualTo("01");
    assertThat(Hex.encode(Arrays.copyOfRange(signature, 1, 5))).isEqualTo("12345678");
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_noPrefix_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa87PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa87PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(MLDSA87_SIGNATURE_BYTES);
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_tinkPrefix_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa87PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa87PublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(5 + MLDSA87_SIGNATURE_BYTES);
    assertThat(Hex.encode(Arrays.copyOf(signature, 1))).isEqualTo("01");
    assertThat(Hex.encode(Arrays.copyOfRange(signature, 1, 5))).isEqualTo("12345678");
    verifier.verify(signature, testData);
  }

  @Test
  public void verify_goldenTestNoPrefix_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa44PublicKey);
    verifier.verify(noPrefixSignatureMlDsa44, messageMlDsa44);
  }

  @Test
  public void verify_goldenTestTink_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa44PublicKey);
    verifier.verify(tinkSignatureMlDsa44, messageMlDsa44);
  }

  @Test
  public void verify_goldenTestNoPrefix_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa65PublicKey);
    verifier.verify(noPrefixSignatureMlDsa65, messageMlDsa65);
  }

  @Test
  public void verify_goldenTestTink_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa65PublicKey);
    verifier.verify(tinkSignatureMlDsa65, messageMlDsa65);
  }

  @Test
  public void verify_goldenTestNoPrefix_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa87PublicKey);
    verifier.verify(noPrefixSignatureMlDsa87, messageMlDsa87);
  }

  @Test
  public void verify_goldenTestTink_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa87PublicKey);
    verifier.verify(tinkSignatureMlDsa87, messageMlDsa87);
  }

  @Test
  public void verify_invalidSignature_fails_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa44PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa44PublicKey);

    byte[] signature = signer.sign(testData);
    signature[0] = (byte) (signature[0] ^ 0xFF); // Corrupt signature

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongOutputPrefix_fails_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa44PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa44PublicKey);

    byte[] signature = signer.sign(testData);
    signature[1] = (byte) (signature[1] ^ 0xFF); // Corrupt prefix byte

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongSignatureLength_fails_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa44PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa44PublicKey);

    byte[] signature = signer.sign(testData);
    byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(shortSignature, testData));
  }

  @Test
  public void verify_invalidSignature_fails_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa65PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa65PublicKey);

    byte[] signature = signer.sign(testData);
    signature[0] = (byte) (signature[0] ^ 0xFF); // Corrupt signature

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongOutputPrefix_fails_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa65PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa65PublicKey);

    byte[] signature = signer.sign(testData);
    signature[1] = (byte) (signature[1] ^ 0xFF); // Corrupt prefix byte

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongSignatureLength_fails_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa65PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa65PublicKey);

    byte[] signature = signer.sign(testData);
    byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(shortSignature, testData));
  }

  @Test
  public void verify_invalidSignature_fails_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(noPrefixMlDsa87PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(noPrefixMlDsa87PublicKey);

    byte[] signature = signer.sign(testData);
    signature[0] = (byte) (signature[0] ^ 0xFF); // Corrupt signature

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongOutputPrefix_fails_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa87PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa87PublicKey);

    byte[] signature = signer.sign(testData);
    signature[1] = (byte) (signature[1] ^ 0xFF); // Corrupt prefix byte

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongSignatureLength_fails_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = MlDsaSigner.create(tinkMlDsa87PrivateKey);
    PublicKeyVerify verifier = MlDsaVerifier.create(tinkMlDsa87PublicKey);

    byte[] signature = signer.sign(testData);
    byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(shortSignature, testData));
  }

  @Test
  public void create_unmatchedKeys_fails_mlDsa44() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    byte[] wrongPublicKeyBytes = noPrefixMlDsa44PublicKey.getSerializedPublicKey().toByteArray();
    wrongPublicKeyBytes[0] ^= 0xFF;
    MlDsaPublicKey wrongPublicKey =
        MlDsaPublicKey.builder()
            .setSerializedPublicKey(Bytes.copyFrom(wrongPublicKeyBytes))
            .setParameters(NO_PREFIX_MLDSA44_PARAMS)
            .build();
    MlDsaPrivateKey wrongPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            wrongPublicKey, noPrefixMlDsa44PrivateKey.getPrivateSeed());

    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(wrongPrivateKey));
  }

  @Test
  public void create_unmatchedKeys_fails_mlDsa65() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    byte[] wrongPublicKeyBytes = noPrefixMlDsa65PublicKey.getSerializedPublicKey().toByteArray();
    wrongPublicKeyBytes[0] ^= 0xFF;
    MlDsaPublicKey wrongPublicKey =
        MlDsaPublicKey.builder()
            .setSerializedPublicKey(Bytes.copyFrom(wrongPublicKeyBytes))
            .setParameters(NO_PREFIX_MLDSA65_PARAMS)
            .build();
    MlDsaPrivateKey wrongPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            wrongPublicKey, noPrefixMlDsa65PrivateKey.getPrivateSeed());

    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(wrongPrivateKey));
  }

  @Test
  public void create_unmatchedKeys_fails_mlDsa87() throws Exception {
    Assume.assumeTrue(MlDsaVerifyConscrypt.isSupported());

    byte[] wrongPublicKeyBytes = noPrefixMlDsa87PublicKey.getSerializedPublicKey().toByteArray();
    wrongPublicKeyBytes[0] ^= 0xFF;
    MlDsaPublicKey wrongPublicKey =
        MlDsaPublicKey.builder()
            .setSerializedPublicKey(Bytes.copyFrom(wrongPublicKeyBytes))
            .setParameters(NO_PREFIX_MLDSA87_PARAMS)
            .build();
    MlDsaPrivateKey wrongPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            wrongPublicKey, noPrefixMlDsa87PrivateKey.getPrivateSeed());

    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(wrongPrivateKey));
  }

  private static final class MlDsaWycheproofTestVector {
    @SuppressWarnings("unused") // provides better readability
    private final int id;

    private final MlDsaInstance instance;
    private final String comment;
    private final byte[] publicKeyBytes;
    private final byte[] msg;
    private final byte[] sig;
    private final String result;
    private final boolean isValidPublicKey;
    private final boolean isValidSig;

    private MlDsaWycheproofTestVector(
        int id,
        MlDsaInstance instance,
        String comment,
        byte[] publicKeyBytes,
        byte[] msg,
        byte[] sig,
        String result,
        boolean isValidPublicKey,
        boolean isValidSig) {
      this.id = id;
      this.instance = instance;
      this.comment = comment;
      this.publicKeyBytes = publicKeyBytes;
      this.msg = msg;
      this.sig = sig;
      this.result = result;
      this.isValidPublicKey = isValidPublicKey;
      this.isValidSig = isValidSig;
    }

    static MlDsaWycheproofTestVector create(
        int id,
        MlDsaInstance instance,
        String comment,
        String publicKeyHex,
        String msgHex,
        String sigHex,
        String result,
        boolean isValidPublicKey,
        boolean isValidSig) {
      return new MlDsaWycheproofTestVector(
          id,
          instance,
          comment,
          Hex.decode(publicKeyHex),
          Hex.decode(msgHex),
          Hex.decode(sigHex),
          result,
          isValidPublicKey,
          isValidSig);
    }

    int getId() {
      return id;
    }

    MlDsaInstance getInstance() {
      return instance;
    }

    String getComment() {
      return comment;
    }

    byte[] getPublicKeyBytes() {
      return publicKeyBytes;
    }

    byte[] getMsg() {
      return msg;
    }

    byte[] getSig() {
      return sig;
    }

    String getResult() {
      return result;
    }

    boolean isValidPublicKey() {
      return isValidPublicKey;
    }

    boolean isValidSig() {
      return isValidSig;
    }
  }

  private static List<MlDsaWycheproofTestVector> readTestVectors(List<String> vectorsFiles)
      throws Exception {
    ArrayList<MlDsaWycheproofTestVector> testVectors = new ArrayList<>();

    for (String vectorsFile : vectorsFiles) {
      JsonObject json;
      try {
        json = WycheproofTestUtil.readJson(vectorsFile);
      } catch (IOException e) {
        throw new IllegalStateException("Failed to read Wycheproof test vectors", e);
      }
      JsonArray testGroups = json.getAsJsonArray("testGroups");
      for (int i = 0; i < testGroups.size(); i++) {
        JsonObject group = testGroups.get(i).getAsJsonObject();
        JsonArray tests = group.getAsJsonArray("tests");

        for (int j = 0; j < tests.size(); j++) {
          JsonObject testCase = tests.get(j).getAsJsonObject();

          // TODO(b/481670005): Handle context when supported.
          if (testCase.has("ctx")) {
            continue;
          }

          int id = testCase.get("tcId").getAsInt();
          String algorithm = json.get("algorithm").getAsString();
          String comment = testCase.get("comment").getAsString();
          String publicKey = group.get("publicKey").getAsString();
          String msg = testCase.get("msg").getAsString();
          String sig = testCase.get("sig").getAsString();
          String result = testCase.get("result").getAsString();
          boolean isValidPublicKey =
              !WycheproofTestUtil.checkFlags(testCase, "IncorrectPublicKeyLength");
          boolean isValidSig = WycheproofTestUtil.checkFlags(testCase, "ValidSignature");

          MlDsaInstance instance;
          if (algorithm.equals("ML-DSA-44")) {
            instance = MlDsaInstance.ML_DSA_44;
          } else if (algorithm.equals("ML-DSA-65")) {
            instance = MlDsaInstance.ML_DSA_65;
          } else if (algorithm.equals("ML-DSA-87")) {
            instance = MlDsaInstance.ML_DSA_87;
          } else {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
          }

          testVectors.add(
              MlDsaWycheproofTestVector.create(
                  id,
                  instance,
                  comment,
                  publicKey,
                  msg,
                  sig,
                  result,
                  isValidPublicKey,
                  isValidSig));
        }
      }
    }
    return Collections.unmodifiableList(testVectors);
  }

  @DataPoints("testVectors")
  public static final List<MlDsaWycheproofTestVector> testVectors =
      exceptionIsBug(
          () ->
              readTestVectors(
                  asList(
                      "third_party/wycheproof/testvectors_v1/mldsa_44_verify_test.json",
                      "third_party/wycheproof/testvectors_v1/mldsa_65_verify_test.json",
                      "third_party/wycheproof/testvectors_v1/mldsa_87_verify_test.json")));

  @Theory
  public void testWycheproofVectors(
      @FromDataPoints("testVectors") MlDsaWycheproofTestVector testVector) throws Exception {
    // In order to avoid the "Never found parameters that satisfied method assumptions" error, here
    // we use an if instead of an assumption.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    String label = "tcId = " + testVector.getId() + ", comment = " + testVector.getComment();

    MlDsaPublicKey publicKey;
    try {
      publicKey =
          MlDsaPublicKey.builder()
              .setParameters(
                  MlDsaParameters.create(
                      testVector.getInstance(), MlDsaParameters.Variant.NO_PREFIX))
              .setSerializedPublicKey(Bytes.copyFrom(testVector.getPublicKeyBytes()))
              .build();
      // Since no exception was thrown, ensure that the key was in fact correct.
      assertTrue(label, testVector.isValidPublicKey());
    } catch (GeneralSecurityException ex) {
      // If an exception was thrown, ensure that the key was in fact invalid.
      assertFalse(label, testVector.isValidPublicKey());
      return;
    }

    PublicKeyVerify verifier = MlDsaVerifier.create(publicKey);
    try {
      verifier.verify(testVector.getSig(), testVector.getMsg());
      assertTrue(label, testVector.isValidSig());
    } catch (GeneralSecurityException ex) {
      assertFalse(label, testVector.isValidSig());
      return;
    }
    assertEquals(label, "valid", testVector.getResult());
  }

  @Test
  public void fips_primitiveCreationFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(tinkMlDsa44PrivateKey));
    assertThrows(GeneralSecurityException.class, () -> MlDsaVerifier.create(tinkMlDsa44PublicKey));
    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(tinkMlDsa65PrivateKey));
    assertThrows(GeneralSecurityException.class, () -> MlDsaVerifier.create(tinkMlDsa65PublicKey));
    assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(tinkMlDsa87PrivateKey));
    assertThrows(GeneralSecurityException.class, () -> MlDsaVerifier.create(tinkMlDsa87PublicKey));
  }
}
