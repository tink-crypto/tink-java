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

package com.google.crypto.tink.mac.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil.AesCmacTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class ChunkedAesCmacConscryptTest {

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  private static boolean conscryptIsAvailable() {
    try {
      return Conscrypt.isAvailable();
    } catch (Throwable e) {
      return false;
    }
  }

  @Nullable private static final Provider CONSCRYPT = getConscryptProviderOrNull();

  @Nullable
  private static Provider getConscryptProviderOrNull() {
    if (Util.isAndroid()) {
      return ConscryptUtil.providerOrNull();
    }
    if (!conscryptIsAvailable()) {
      return null;
    }
    return Conscrypt.newProvider();
  }

  private static boolean supportsAesCmac(Provider provider) {
    if (provider == null) {
      return false;
    }
    try {
      javax.crypto.Mac unused = javax.crypto.Mac.getInstance("AESCMAC", provider);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  @DataPoints("parameters")
  public static final AesCmacParameters[] parameters = {
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 11, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 12, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 13, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 14, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 15, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.LEGACY),
  };

  @Theory
  public void computeAndVerifyMac_isCompatibleWithMacPrimitive(
      @FromDataPoints("parameters") AesCmacParameters parameters) throws Exception {
    // We don't use assumeTrue here because we don't want this to fail if Conscrypt does not
    // support AES-CMAC.
    if (!supportsAesCmac(CONSCRYPT)) {
      return;
    }
    byte[] data0 = new byte[] {1, 2, 3};
    byte[] data1 = new byte[] {4, 5, 6};
    byte[] data = new byte[] {1, 2, 3, 4, 5, 6};  // concat of data0 and data1
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters)
                    .withFixedId(1234)
                    .makePrimary())
            .build();
    Mac mac = keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    byte[] expectedTag = mac.computeMac(data);
    AesCmacKey key = (AesCmacKey) keysetHandle.getAt(0).getKey();
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(key, CONSCRYPT);

    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();
    chunkedMacComputation.update(ByteBuffer.wrap(data0));
    chunkedMacComputation.update(ByteBuffer.wrap(data1));
    byte[] tag = chunkedMacComputation.computeMac();
    ChunkedMacVerification macVerification = chunkedMac.createVerification(tag);
    macVerification.update(ByteBuffer.wrap(data0));
    macVerification.update(ByteBuffer.wrap(data1));
    macVerification.verifyMac();

    // AES-CMAC is deterministic, so the tag should be the same.
    assertThat(tag).isEqualTo(expectedTag);
  }

  // Test data from https://tools.ietf.org/html/rfc4493#section-4.
  @DataPoints("cmacTestVectorsFromRfc")
  public static final AesCmacTestVector[] cmacTestVectorsFromRfc =
      new AesCmacTestVector[] {
        AesCmacTestUtil.RFC_TEST_VECTOR_0,
        AesCmacTestUtil.RFC_TEST_VECTOR_1,
        AesCmacTestUtil.RFC_TEST_VECTOR_2
      };

  @Theory
  public void computeAndVerifyMac_works(
      @FromDataPoints("cmacTestVectorsFromRfc") AesCmacTestVector t) throws Exception {
    // We don't use assumeTrue here because we don't want this to fail if Conscrypt does not
    // support AES-CMAC.
    if (!supportsAesCmac(CONSCRYPT)) {
      return;
    }
    ChunkedMac mac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(t.message));
    byte[] tag = macComputation.computeMac();
    ChunkedMacVerification macVerification = mac.createVerification(t.tag);
    macVerification.update(ByteBuffer.wrap(t.message));
    macVerification.verifyMac();

    assertThat(tag).isEqualTo(t.tag);
  }

  @Test
  public void computeAndVerifyMac_withReadOnlyBuffer_works() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_0;
    ChunkedMac mac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
    byte[] tag = macComputation.computeMac();
    ChunkedMacVerification macVerification = mac.createVerification(t.tag);
    macVerification.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
    macVerification.verifyMac();

    assertThat(tag).isEqualTo(t.tag);
  }

  @Test
  public void verifyMac_truncatedTag_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_0;
    byte[] truncatedTag = Arrays.copyOf(t.tag, t.tag.length - 1);
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacVerification macVerification = chunkedMac.createVerification(truncatedTag);
    macVerification.update(ByteBuffer.wrap(t.message));

    assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
  }

  @Test
  public void verifyMac_bitFlipMessage_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_1;
    byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
    modifiedMessage[0] = (byte) (modifiedMessage[0] ^ 1);
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacVerification macVerification = chunkedMac.createVerification(t.tag);
    macVerification.update(ByteBuffer.wrap(modifiedMessage));

    assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
  }

  @Test
  public void verifyMac_bitFlipTag_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_0;
    byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
    modifiedTag[0] = (byte) (modifiedTag[0] ^ 1);
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacVerification macVerification = chunkedMac.createVerification(modifiedTag);
    macVerification.update(ByteBuffer.wrap(t.message));

    assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
  }

  @Test
  public void updateAfterComputeMac_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));

    ChunkedMac chunkedMac =
        ChunkedAesCmacConscrypt.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key, CONSCRYPT);
    ChunkedMacComputation macComputation = chunkedMac.createComputation();
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    byte[] unused = macComputation.computeMac();

    assertThrows(
        IllegalStateException.class,
        () -> macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message)));
  }

  @Test
  public void computeMacAfterComputeMac_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));

    ChunkedMac chunkedMac =
        ChunkedAesCmacConscrypt.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key, CONSCRYPT);
    ChunkedMacComputation macComputation = chunkedMac.createComputation();
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    byte[] unused = macComputation.computeMac();

    assertThrows(IllegalStateException.class, macComputation::computeMac);
  }

  @Test
  public void updateAfterVerifyMac_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));

    ChunkedMac chunkedMac =
        ChunkedAesCmacConscrypt.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key, CONSCRYPT);
    ChunkedMacVerification macVerification =
        chunkedMac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();

    assertThrows(
        IllegalStateException.class,
        () -> macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message)));
  }

  @Test
  public void verifyMacAfterVerifyMac_throwsGeneralSecurityException() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));

    ChunkedMac chunkedMac =
        ChunkedAesCmacConscrypt.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key, CONSCRYPT);
    ChunkedMacVerification macVerification =
        chunkedMac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();

    assertThrows(IllegalStateException.class, macVerification::verifyMac);
  }

  @Test
  public void computeAndVerifyMac_withWycheproofVectors_works() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors/aes_cmac_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int tagSize = group.get("tagSize").getAsInt();
      int keySize = group.get("keySize").getAsInt();
      if (keySize == 192) {
        // our implementation does not support 192-bit keys.
        continue;
      }

      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testCase.get("tcId").getAsInt(), testCase.get("comment").getAsString());
        byte[] key = Hex.decode(testCase.get("key").getAsString());
        byte[] msg = Hex.decode(testCase.get("msg").getAsString());
        byte[] tag = Hex.decode(testCase.get("tag").getAsString());
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext and tag.
        // "invalid" are test vectors with invalid parameters or invalid tag.
        // "acceptable" are test vectors with weak parameters or legacy formats, but there are no
        // "acceptable" tests cases for Aes Cmac.
        String result = testCase.get("result").getAsString();
        if (!result.equals("valid") && !result.equals("invalid")) {
          errors.add("FAIL " + tcId + ": result is not valid or invalid");
        }

        try {
          AesCmacParameters noPrefixParameters =
              AesCmacParameters.builder()
                  .setTagSizeBytes(tagSize / 8)
                  .setKeySizeBytes(keySize / 8).build();
          AesCmacKey aesCmacKey =
              AesCmacKey.builder()
                  .setAesKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
                  .setParameters(noPrefixParameters).build();

          ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(aesCmacKey, CONSCRYPT);

          ChunkedMacComputation macComputation = chunkedMac.createComputation();
          macComputation.update(ByteBuffer.wrap(msg));
          assertThat(tag).isEqualTo(macComputation.computeMac());

          ChunkedMacVerification macVerification = chunkedMac.createVerification(tag);
          macVerification.update(ByteBuffer.wrap(msg));
          macVerification.verifyMac();

          // If the test is "invalid" but no exception is thrown, it's an error.
          if (result.equals("invalid")) {
            errors.add("FAIL " + tcId + ": invalid Wycheproof test did not fail");
          }
        } catch (GeneralSecurityException | AssertionError ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + ": Wycheproof test failed, exception " + ex);
          }
        }
      }
    }
    assertThat(errors).isEmpty();
  }

  @DataPoints("invalidTagTestVectors")
  public static final AesCmacTestVector[] invalidTagTestVectors =
      new AesCmacTestVector[] {
        AesCmacTestUtil.WRONG_PREFIX_TAG_LEGACY,
        AesCmacTestUtil.WRONG_PREFIX_TAG_TINK,
        AesCmacTestUtil.TAG_TOO_SHORT
      };

  @Theory
  public void createVerification_invalidTag_throwsGeneralSecurityException(
      @FromDataPoints("invalidTagTestVectors") AesCmacTestVector t) throws Exception {
    // We don't use assumeTrue here because we don't want this to fail if Conscrypt does not
    // support AES-CMAC.
    if (!supportsAesCmac(CONSCRYPT)) {
      return;
    }
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    assertThrows(GeneralSecurityException.class, () -> chunkedMac.createVerification(t.tag));
  }

  @Test
  public void modifyTagAfterCreation_verifyMac_works() throws Exception {
    assumeTrue(supportsAesCmac(CONSCRYPT));
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_0;
    byte[] mutableTag = Arrays.copyOf(t.tag, t.tag.length);
    ChunkedMac chunkedMac = ChunkedAesCmacConscrypt.create(t.key, CONSCRYPT);

    ChunkedMacVerification macVerification = chunkedMac.createVerification(mutableTag);
    mutableTag[0] ^= (byte) 0x01;
    macVerification.update(ByteBuffer.wrap(t.message));

    macVerification.verifyMac();
  }

  @Test
  public void create_conscryptIsNull_throwsIllegalArgumentException() throws Exception {
    AesCmacTestVector t = AesCmacTestUtil.RFC_TEST_VECTOR_0;

    assertThrows(IllegalArgumentException.class, () -> ChunkedAesCmacConscrypt.create(t.key, null));
  }
}
