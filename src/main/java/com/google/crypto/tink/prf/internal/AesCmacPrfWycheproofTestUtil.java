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
package com.google.crypto.tink.prf.internal;

import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Utility class for reading Wycheproof test vectors for AES-CMAC PRFs. */
public final class AesCmacPrfWycheproofTestUtil {

  public static final List<AesCmacPrfTestUtil.TestVector> readTestVectors() {
    ArrayList<AesCmacPrfTestUtil.TestVector> testVectors = new ArrayList<>();

    JsonObject json;
    try{
      json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors_v1/aes_cmac_test.json");
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read Wycheproof test vectors", e);
    }
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int keySize = group.get("keySize").getAsInt();
      if (keySize == 192) {
        // 192-bit keys are not supported.
        continue;
      }
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        String result = testCase.get("result").getAsString();
        if (result.equals("invalid")) {
          continue;
        }
        String keyHex = testCase.get("key").getAsString();
        String dataHex = testCase.get("msg").getAsString();
        String outputHex = testCase.get("tag").getAsString();
        int outputLength = Hex.decode(outputHex).length;
        testVectors.add(
            AesCmacPrfTestUtil.TestVector.create(keyHex, dataHex, outputLength, outputHex));
      }
    }
    return Collections.unmodifiableList(testVectors);
  }

  private AesCmacPrfWycheproofTestUtil() {
  }
}
