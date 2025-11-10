// Copyright 2023 Google LLC
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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Represents a key for computing JWT ECDSA signatures (ES256, ES384, ES512).
 *
 * <p>See https://datatracker.ietf.org/doc/html/rfc7518 for more information.
 */
@Immutable
public final class JwtEcdsaPrivateKey extends JwtSignaturePrivateKey {
  public final JwtEcdsaPublicKey publicKey;
  private final EcdsaPrivateKey ecdsaPrivateKey;

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public static JwtEcdsaPrivateKey create(
      JwtEcdsaPublicKey publicKey, SecretBigInteger privateValue) throws GeneralSecurityException {
    EcdsaPrivateKey ecdsaPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey.getEcdsaPublicKey())
            .setPrivateValue(privateValue)
            .build();
    return new JwtEcdsaPrivateKey(publicKey, ecdsaPrivateKey);
  }

  private JwtEcdsaPrivateKey(JwtEcdsaPublicKey publicKey, EcdsaPrivateKey ecdsaPrivateKey) {
    this.publicKey = publicKey;
    this.ecdsaPrivateKey = ecdsaPrivateKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public SecretBigInteger getPrivateValue() {
    return ecdsaPrivateKey.getPrivateValue();
  }

  @Override
  public JwtEcdsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public JwtEcdsaPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtEcdsaPrivateKey)) {
      return false;
    }
    JwtEcdsaPrivateKey that = (JwtEcdsaPrivateKey) o;
    return that.publicKey.equalsKey(publicKey) && ecdsaPrivateKey.equalsKey(that.ecdsaPrivateKey);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  EcdsaPrivateKey getEcdsaPrivateKey() {
    return ecdsaPrivateKey;
  }
}
