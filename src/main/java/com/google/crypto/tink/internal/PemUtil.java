// Copyright 2026 Google LLC
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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.subtle.Base64;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.annotation.Nullable;

/** Utility class for parsing PEM keys. */
public final class PemUtil {

  private static final String PUBLIC_KEY = "PUBLIC KEY";
  private static final String PRIVATE_KEY = "PRIVATE KEY";
  private static final String BEGIN = "-----BEGIN ";
  private static final String END = "-----END ";
  private static final String MARKER = "-----";

  /**
   * Parses a single key from {@code reader}.
   *
   * <p>For private keys, it will return a PKCS8EncodedKeySpec. For public keys, it will return a
   * X509EncodedKeySpec.
   */
  @Nullable
  public static EncodedKeySpec parsePemToKeySpec(BufferedReader reader) throws IOException {
    String line = reader.readLine();
    while (line != null && !line.startsWith(BEGIN)) {
      line = reader.readLine();
    }
    if (line == null) {
      return null;
    }

    line = line.trim().substring(BEGIN.length());
    int index = line.indexOf(MARKER);
    if (index < 0) {
      return null;
    }
    String type = line.substring(0, index);
    String endMarker = END + type + MARKER;
    StringBuilder base64key = new StringBuilder();

    while ((line = reader.readLine()) != null) {
      if (line.indexOf(":") > 0) {
        // header, ignore
        continue;
      }
      if (line.contains(endMarker)) {
        break;
      }
      base64key.append(line);
    }
    byte[] key = Base64.decode(base64key.toString(), Base64.DEFAULT);
    if (type.contains(PUBLIC_KEY)) {
      return new X509EncodedKeySpec(key);
    } else if (type.contains(PRIVATE_KEY)) {
      return new PKCS8EncodedKeySpec(key);
    }
    return null;
  }

  private PemUtil() {}
}
