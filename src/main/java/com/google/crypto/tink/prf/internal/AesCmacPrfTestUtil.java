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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Utility class for testing AES-CMAC PRFs. */
@AccessesPartialKey
public final class AesCmacPrfTestUtil {

  /** Test vector for AES-CMAC Prf primitive. */
  public static class AesCmacPrfTestVector {
    private final AesCmacPrfKey key;
    private final byte[] data;
    private final byte[] output;
    private final int outputLength;

    private AesCmacPrfTestVector(String key, String data, int outputLength, String output) {
      try {
        byte[] keyBytes = Hex.decode(key);
        this.key =
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(keyBytes.length),
                SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()));
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
      this.data = Hex.decode(data);
      this.outputLength = outputLength;
      this.output = Hex.decode(output);
    }

    public AesCmacPrfKey key() {
      return key;
    }

    /** Returns the input data. Do not modify. */
    public byte[] data() {
      return data;
    }

    /** Returns the expected output. Do not modify. */
    public byte[] output() {
      return output;
    }

    public int outputLength() {
      return outputLength;
    }
  }

  public static final List<AesCmacPrfTestVector> creatTestVectors() {
    ArrayList<AesCmacPrfTestVector> testVectors = new ArrayList<>();

    // test vectors from https://tools.ietf.org/html/rfc4493#section-4
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "2b7e151628aed2a6abf7158809cf4f3c",
            /* data= */ "",
            /* outputLength= */ 16,
            /* output= */ "bb1d6929e95937287fa37d129b756746"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "2b7e151628aed2a6abf7158809cf4f3c",
            /* data= */ "",
            /* outputLength= */ 8,
            /* output= */ "bb1d6929e9593728"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "2b7e151628aed2a6abf7158809cf4f3c",
            /* data= */ "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411",
            /* outputLength= */ 16,
            /* output= */ "dfa66747de9ae63030ca32611497c827"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "2b7e151628aed2a6abf7158809cf4f3c",
            /* data= */ "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710",
            /* outputLength= */ 16,
            /* output= */ "51f0bebf7e3b9d92fc49741779363cfe"));

    // test vector with 32-byte key from
    // https://github.com/C2SP/wycheproof/blob/master/testvectors/aes_cmac_test.json
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97",
            /* data= */ "",
            /* outputLength= */ 16,
            /* output= */ "736c7b56957db774c5ddf7c7a70ba8a8"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "c19bdf314c6cf64381425467f42aefa17c1cc9358be16ce31b1d214859ce86aa",
            /* data= */ "5d066a92c300e9b6ddd63a7c13ae33",
            /* outputLength= */ 16,
            /* output= */ "b96818b7acaf879c7a7f8271375a6914"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "612e837843ceae7f61d49625faa7e7494f9253e20cb3adcea686512b043936cd",
            /* data= */ "cc37fae15f745a2f40e2c8b192f2b38d",
            /* outputLength= */ 16,
            /* output= */ "4b88e193000c5a4b23e95c7f2b26530b"));
    testVectors.add(
        new AesCmacPrfTestVector(
            /* key= */ "73216fafd0022d0d6ee27198b2272578fa8f04dd9f44467fbb6437aa45641bf7",
            /* data= */ "d5247b8f6c3edcbfb1d591d13ece23d2f5",
            /* outputLength= */ 16,
            /* output= */ "86911c7da51dc0823d6e93d4290d1ad4"));
    return Collections.unmodifiableList(testVectors);
  }

  private AesCmacPrfTestUtil() {}
}
