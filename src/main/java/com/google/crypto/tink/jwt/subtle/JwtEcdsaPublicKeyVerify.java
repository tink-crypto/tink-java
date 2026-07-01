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

package com.google.crypto.tink.jwt.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.errorprone.annotations.RestrictedApi;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** An implementation of {@link JwtPublicKeyVerify} for ECDSA. */
@SuppressWarnings("Immutable") // EcdsaVerifyJce.create returns an immutable verifier.
public final class JwtEcdsaPublicKeyVerify implements JwtPublicKeyVerify {
  private final JwtEcdsaPublicKey publicKey;
  private final PublicKeyVerify verifier;

  private JwtEcdsaPublicKeyVerify(JwtEcdsaPublicKey publicKey, PublicKeyVerify verifier) {
    this.publicKey = publicKey;
    this.verifier = verifier;
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  @AccessesPartialKey
  public static JwtPublicKeyVerify create(JwtEcdsaPublicKey publicKey) throws GeneralSecurityException {
    return new JwtEcdsaPublicKeyVerify(
        publicKey, EcdsaVerifyJce.create(publicKey.getEcdsaPublicKey()));
  }

  @Override
  public VerifiedJwt verifyAndDecode(String compact, JwtValidator validator)
      throws GeneralSecurityException {
    JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
    verifier.verify(
        parts.signatureOrMac, parts.unsignedCompact.getBytes(StandardCharsets.US_ASCII));
    JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
    JwtFormat.validateHeader(
        parsedHeader,
        publicKey.getParameters().getAlgorithm().getStandardName(),
        publicKey.getKid(),
        publicKey.getParameters().allowKidAbsent());
    RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
    return validator.unsafeValidate(token);
  }
}
