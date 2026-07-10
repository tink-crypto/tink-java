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

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/** An implementation of {@link JwtPublicKeySign} for RSA SSA PSS. */
@SuppressWarnings("Immutable") // RsaSsaPssSignJce.create returns an immutable signer.
public final class JwtRsaSsaPssPublicKeySign implements JwtPublicKeySign {
  private final JwtRsaSsaPssPrivateKey privateKey;
  private final PublicKeySign signer;
  private final String algorithm;

  private JwtRsaSsaPssPublicKeySign(
      JwtRsaSsaPssPrivateKey privateKey, PublicKeySign signer, String algorithm) {
    this.privateKey = privateKey;
    this.signer = signer;
    this.algorithm = algorithm;
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  @AccessesPartialKey
  public static JwtPublicKeySign create(JwtRsaSsaPssPrivateKey privateKey)
      throws GeneralSecurityException {
    return new JwtRsaSsaPssPublicKeySign(
        privateKey,
        RsaSsaPssSignJce.create(privateKey.getRsaSsaPssPrivateKey()),
        privateKey.getParameters().getAlgorithm().getStandardName());
  }

  @Override
  public String signAndEncode(RawJwt rawJwt) throws GeneralSecurityException {
    String unsignedCompact =
        JwtFormat.createUnsignedCompact(algorithm, privateKey.getPublicKey().getKid(), rawJwt);
    return JwtFormat.createSignedCompact(
        unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
  }
}
