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
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Represents a private key for RSA SSA PKCS1 signatures (RS256, RS384, RS512).
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc7518
 */
public final class JwtRsaSsaPkcs1PrivateKey extends JwtSignaturePrivateKey {
  private final JwtRsaSsaPkcs1PublicKey publicKey;
  private final RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey;

  /** Builder for JwtRsaSsaPkcs1PrivateKey. */
  public static class Builder {
    private Optional<JwtRsaSsaPkcs1PublicKey> publicKey = Optional.empty();
    private Optional<SecretBigInteger> d = Optional.empty();
    private Optional<SecretBigInteger> p = Optional.empty();
    private Optional<SecretBigInteger> q = Optional.empty();
    private Optional<SecretBigInteger> dP = Optional.empty();
    private Optional<SecretBigInteger> dQ = Optional.empty();
    private Optional<SecretBigInteger> qInv = Optional.empty();
    private Optional<RsaSsaPkcs1PrivateKey> rsaSsaPkcs1PrivateKey = Optional.empty();

    private Builder() {}

    /**
     * Sets the public key, which includes the parameters.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPublicKey(JwtRsaSsaPkcs1PublicKey publicKey) {
      this.publicKey = Optional.of(publicKey);
      return this;
    }

    @CanIgnoreReturnValue
    Builder setRsaSsaPkcs1PrivateKey(RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey) {
      this.rsaSsaPkcs1PrivateKey = Optional.of(rsaSsaPkcs1PrivateKey);
      return this;
    }

    /**
     * Sets the prime factors p and q.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimes(SecretBigInteger p, SecretBigInteger q) {
      this.p = Optional.of(p);
      this.q = Optional.of(q);
      return this;
    }

    /**
     * Sets the private exponent d.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrivateExponent(SecretBigInteger d) {
      this.d = Optional.of(d);
      return this;
    }

    /**
     * Sets the prime exponents dP and dQ.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimeExponents(SecretBigInteger dP, SecretBigInteger dQ) {
      this.dP = Optional.of(dP);
      this.dQ = Optional.of(dQ);
      return this;
    }

    /**
     * Sets the CRT coefficient qInv.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setCrtCoefficient(SecretBigInteger qInv) {
      this.qInv = Optional.of(qInv);
      return this;
    }

    @AccessesPartialKey
    public JwtRsaSsaPkcs1PrivateKey build() throws GeneralSecurityException {
      if (!publicKey.isPresent()) {
        throw new GeneralSecurityException("Cannot build without a RSA SSA PKCS1 public key");
      }
      if (rsaSsaPkcs1PrivateKey.isPresent()) {
        if (p.isPresent()
            || q.isPresent()
            || d.isPresent()
            || dP.isPresent()
            || dQ.isPresent()
            || qInv.isPresent()) {
          throw new GeneralSecurityException(
              "Cannot build with a RSA SSA PKCS1 private key and other private key components");
        }
        if (!rsaSsaPkcs1PrivateKey
            .get()
            .getPublicKey()
            .equalsKey(publicKey.get().getRsaSsaPkcs1PublicKey())) {
          throw new GeneralSecurityException("public key does not match the private key");
        }
        return new JwtRsaSsaPkcs1PrivateKey(publicKey.get(), rsaSsaPkcs1PrivateKey.get());
      }
      if (!p.isPresent() || !q.isPresent()) {
        throw new GeneralSecurityException("Cannot build without prime factors");
      }
      if (!d.isPresent()) {
        throw new GeneralSecurityException("Cannot build without private exponent");
      }
      if (!dP.isPresent() || !dQ.isPresent()) {
        throw new GeneralSecurityException("Cannot build without prime exponents");
      }
      if (!qInv.isPresent()) {
        throw new GeneralSecurityException("Cannot build without CRT coefficient");
      }

      return new JwtRsaSsaPkcs1PrivateKey(
          publicKey.get(),
          RsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(publicKey.get().getRsaSsaPkcs1PublicKey())
              .setPrimes(p.get(), q.get())
              .setPrivateExponent(d.get())
              .setPrimeExponents(dP.get(), dQ.get())
              .setCrtCoefficient(qInv.get())
              .build());
    }
  }

  private JwtRsaSsaPkcs1PrivateKey(
      JwtRsaSsaPkcs1PublicKey publicKey, RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey) {
    this.publicKey = publicKey;
    this.rsaSsaPkcs1PrivateKey = rsaSsaPkcs1PrivateKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  /** Returns the key parameters. */
  @Override
  public JwtRsaSsaPkcs1Parameters getParameters() {
    return publicKey.getParameters();
  }

  /** Returns the public key. */
  @Override
  public JwtRsaSsaPkcs1PublicKey getPublicKey() {
    return publicKey;
  }

  /** Returns the prime factor p. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public SecretBigInteger getPrimeP() {
    return rsaSsaPkcs1PrivateKey.getPrimeP();
  }

  /** Returns the prime factor q. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public SecretBigInteger getPrimeQ() {
    return rsaSsaPkcs1PrivateKey.getPrimeQ();
  }

  /** Returns the private exponent d. */
  @AccessesPartialKey
  public SecretBigInteger getPrivateExponent() {
    return rsaSsaPkcs1PrivateKey.getPrivateExponent();
  }

  /** Returns the prime exponent dP. */
  @AccessesPartialKey
  public SecretBigInteger getPrimeExponentP() {
    return rsaSsaPkcs1PrivateKey.getPrimeExponentP();
  }

  /** Returns the prime exponent dQ. */
  @AccessesPartialKey
  public SecretBigInteger getPrimeExponentQ() {
    return rsaSsaPkcs1PrivateKey.getPrimeExponentQ();
  }

  /** Returns the CRT coefficient qInv. */
  @AccessesPartialKey
  public SecretBigInteger getCrtCoefficient() {
    return rsaSsaPkcs1PrivateKey.getCrtCoefficient();
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtRsaSsaPkcs1PrivateKey)) {
      return false;
    }
    JwtRsaSsaPkcs1PrivateKey that = (JwtRsaSsaPkcs1PrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && that.rsaSsaPkcs1PrivateKey.equalsKey(rsaSsaPkcs1PrivateKey);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  RsaSsaPkcs1PrivateKey getRsaSsaPkcs1PrivateKey() {
    return rsaSsaPkcs1PrivateKey;
  }
}
