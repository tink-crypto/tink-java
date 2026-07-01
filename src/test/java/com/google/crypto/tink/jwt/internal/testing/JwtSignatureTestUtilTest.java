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

package com.google.crypto.tink.jwt.internal.testing;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.PublicKeySign;
import com.google.gson.JsonObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class JwtSignatureTestUtilTest {

  @Test
  public void generateSignedCompact_success() throws Exception {
    PublicKeySign fakeSigner = data -> "signature".getBytes(UTF_8);
    JsonObject header = new JsonObject();
    header.addProperty("alg", "ES256");
    JsonObject payload = new JsonObject();
    payload.addProperty("sub", "subject");

    String signedCompact = JwtSignatureTestUtil.generateSignedCompact(fakeSigner, header, payload);

    assertThat(signedCompact)
        .isEqualTo("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0In0.c2lnbmF0dXJl");
  }
}
