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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Represents a key for computing JWT ML-DSA signatures (ML-DSA-44, ML-DSA-65, ML-DSA-87).
 *
 * <p>See https://www.rfc-editor.org/rfc/rfc9964.html for more information.
 */
@Immutable
public final class JwtMlDsaPrivateKey extends JwtSignaturePrivateKey {
  private final JwtMlDsaPublicKey publicKey;
  private final MlDsaPrivateKey mlDsaPrivateKey;

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public static JwtMlDsaPrivateKey create(JwtMlDsaPublicKey publicKey, SecretBytes privateSeed)
      throws GeneralSecurityException {
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(publicKey.getMlDsaPublicKey(), privateSeed);
    return new JwtMlDsaPrivateKey(publicKey, mlDsaPrivateKey);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  static JwtMlDsaPrivateKey create(JwtMlDsaPublicKey publicKey, MlDsaPrivateKey mlDsaPrivateKey)
      throws GeneralSecurityException {
    if (!mlDsaPrivateKey.getPublicKey().equalsKey(publicKey.getMlDsaPublicKey())) {
      throw new GeneralSecurityException("public key does not match the private key");
    }
    return new JwtMlDsaPrivateKey(publicKey, mlDsaPrivateKey);
  }

  private JwtMlDsaPrivateKey(JwtMlDsaPublicKey publicKey, MlDsaPrivateKey mlDsaPrivateKey) {
    this.publicKey = publicKey;
    this.mlDsaPrivateKey = mlDsaPrivateKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public SecretBytes getPrivateSeed() {
    return mlDsaPrivateKey.getPrivateSeed();
  }

  @Override
  public JwtMlDsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public JwtMlDsaPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtMlDsaPrivateKey)) {
      return false;
    }
    JwtMlDsaPrivateKey that = (JwtMlDsaPrivateKey) o;
    return publicKey.equalsKey(that.publicKey) && mlDsaPrivateKey.equalsKey(that.mlDsaPrivateKey);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public MlDsaPrivateKey getMlDsaPrivateKey() {
    return mlDsaPrivateKey;
  }
}
