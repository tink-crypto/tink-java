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

package com.google.crypto.tink.jwt.subtle;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.jwt.JwtHmacKey;
import com.google.crypto.tink.jwt.JwtHmacParameters;
import com.google.crypto.tink.jwt.JwtMac;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/** An implementation of {@link JwtMac} for HMAC. */
@Immutable
public final class JwtHmac implements JwtMac {
  @SuppressWarnings("Immutable") // Mac objects obtained from PrfMac.create are immutable.
  private final Mac mac;

  private final String algorithm;
  private final JwtHmacKey jwtHmacKey;

  private JwtHmac(Mac plainMac, JwtHmacKey jwtHmacKey) {
    this.algorithm = jwtHmacKey.getParameters().getAlgorithm().getStandardName();
    this.mac = plainMac;
    this.jwtHmacKey = jwtHmacKey;
  }

  private static void validate(JwtHmacParameters parameters) throws GeneralSecurityException {
    int minKeySize = Integer.MAX_VALUE;
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS256)) {
      minKeySize = 32;
    }
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS384)) {
      minKeySize = 48;
    }
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS512)) {
      minKeySize = 64;
    }
    if (parameters.getKeySizeBytes() < minKeySize) {
      throw new GeneralSecurityException("Key size must be at least " + minKeySize);
    }
  }

  private static int getTagLength(JwtHmacParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS256)) {
      return 32;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS384)) {
      return 48;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS512)) {
      return 64;
    }
    throw new GeneralSecurityException("Unsupported algorithm: " + algorithm);
  }

  private static HmacParameters.HashType getHmacHashType(JwtHmacParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS256)) {
      return HmacParameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS384)) {
      return HmacParameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS512)) {
      return HmacParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("Unsupported algorithm: " + algorithm);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  @AccessesPartialKey
  public static JwtMac create(JwtHmacKey key) throws GeneralSecurityException {
    validate(key.getParameters());
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setKeySizeBytes(key.getParameters().getKeySizeBytes())
                    .setHashType(getHmacHashType(key.getParameters().getAlgorithm()))
                    .setTagSizeBytes(getTagLength(key.getParameters().getAlgorithm()))
                    .build())
            .setKeyBytes(key.getKeyBytes())
            .build();
    return new JwtHmac(PrfMac.create(hmacKey), key);
  }

  @Override
  public String computeMacAndEncode(RawJwt rawJwt) throws GeneralSecurityException {
    String unsignedCompact =
        JwtFormat.createUnsignedCompact(algorithm, jwtHmacKey.getKid(), rawJwt);
    return JwtFormat.createSignedCompact(
        unsignedCompact, mac.computeMac(unsignedCompact.getBytes(US_ASCII)));
  }

  @Override
  public VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
      throws GeneralSecurityException {
    JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
    mac.verifyMac(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
    JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
    JwtFormat.validateHeader(
        parsedHeader,
        jwtHmacKey.getParameters().getAlgorithm().getStandardName(),
        jwtHmacKey.getKid(),
        jwtHmacKey.getParameters().allowKidAbsent());
    RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
    return validator.unsafeValidate(token);
  }
}
