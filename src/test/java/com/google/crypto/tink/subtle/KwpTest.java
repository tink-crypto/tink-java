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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyWrap;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Kwp}. */
@RunWith(JUnit4.class)
public class KwpTest {

  @Test
  public void testWrapUnwrapMsgSizes() throws Exception {
    byte[] wrapKey = Random.randBytes(16);
    KeyWrap wrapper = new Kwp(wrapKey);
    for (int wrappedSize = 16; wrappedSize < 128; wrappedSize++) {
      byte[] keyMaterialToWrap = Random.randBytes(wrappedSize);
      byte[] wrapped = wrapper.wrap(keyMaterialToWrap);
      byte[] unwrapped = wrapper.unwrap(wrapped);
      assertArrayEquals(keyMaterialToWrap, unwrapped);
    }
  }

  @Test
  public void testInvalidKeySizes() throws Exception {
    // Tests the wrapping key. Its key size is either 16 or 32.
    for (int j = 0; j < 255; j++) {
      final int i = j;
      if (i == 16 || i == 32) {
        continue;
      }
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            KeyWrap unused = new Kwp(new byte[i]);
          });
    }
  }

  @Test
  public void testInvalidWrappingSizes() throws Exception {
    byte[] wrapKey = Random.randBytes(16);
    KeyWrap wrapper = new Kwp(wrapKey);
    for (int i = 0; i < 16; i++) {
      final int wrappedSize = i;
      assertThrows(GeneralSecurityException.class, () -> wrapper.wrap(new byte[wrappedSize]));
    }
  }

  @Test
  public void testWycheproof() throws Exception {
    final String expectedVersion = "0.6";
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/kwp_test.json");
    String generatorVersion = json.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.printf("Expecting test vectors with version %s found version %s.\n",
                        expectedVersion, generatorVersion);
    }
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] data = Hex.decode(testcase.get("msg").getAsString());
        byte[] expected = Hex.decode(testcase.get("ct").getAsString());
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        // Test wrapping
        KeyWrap wrapper;
        try {
          wrapper = new Kwp(key);
        } catch (GeneralSecurityException ex) {
          // tink restrict the key sizes to 128 or 256 bits.
          if (key.length == 16 || key.length == 32) {
            errors.add("FAIL " + tc + ": Rejected valid key, exception: " + ex);
          }
          continue;
        }
        try {
          byte[] wrapped = wrapper.wrap(data);
          boolean eq = TestUtil.arrayEquals(expected, wrapped);
          if (result.equals("invalid")) {
            if (eq) {
              errors.add("FAIL " + tc + ": Accepted invalid parameters");
            }
          } else {
            if (!eq) {
              errors.add("FAIL " + tc + ": Incorrect wrapping:" + Hex.encode(wrapped));
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tc + ": rejected valid test case, exception: "+ ex);
          }
        } catch (Exception ex) {
          errors.add("FAIL " + tc + " throws unexpected exception: " + ex);
        }

        // Test unwrapping
        // The algorithms tested in this class are typically malleable. Hence, it is in possible
        // that modifying ciphertext randomly results in some other valid ciphertext.
        // However, all the test vectors in Wycheproof are constructed such that they have
        // invalid padding. If this changes then the test below is too strict.
        try {
          byte[] unwrapped = wrapper.unwrap(expected);
          boolean eq = TestUtil.arrayEquals(data, unwrapped);
          if (result.equals("invalid")) {
            errors.add(
                "FAIL "
                    + tc
                    + ": Invalid test case unwrapped with output: "
                    + Hex.encode(unwrapped));
          } else {
            if (!eq) {
              errors.add(
                  "FAIL "
                      + tc
                      + ": Incorrect unwrap. Excepted:"
                      + Hex.encode(data)
                      + " actual:"
                      + Hex.encode(unwrapped));
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tc + ": failed with valid test case, exception: " + ex);
          }
        } catch (Exception ex) {
          errors.add("FAIL " + tc + ": throws unexpected exception: " + ex);
        }
      }
    }
    assertThat(errors).isEmpty();
  }
}
