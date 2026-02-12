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
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Represents a private key for RSA SSA PSS signatures (PS256, PS384, PS512).
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc7518
 */
public final class JwtRsaSsaPssPrivateKey extends JwtSignaturePrivateKey {
  private final JwtRsaSsaPssPublicKey publicKey;
  private final RsaSsaPssPrivateKey rsaSsaPssPrivateKey;

  /** Builder for JwtRsaSsaPssPrivateKey. */
  public static class Builder {
    private Optional<JwtRsaSsaPssPublicKey> publicKey = Optional.empty();
    private Optional<SecretBigInteger> d = Optional.empty();
    private Optional<SecretBigInteger> p = Optional.empty();
    private Optional<SecretBigInteger> q = Optional.empty();
    private Optional<SecretBigInteger> dP = Optional.empty();
    private Optional<SecretBigInteger> dQ = Optional.empty();
    private Optional<SecretBigInteger> qInv = Optional.empty();
    private Optional<RsaSsaPssPrivateKey> rsaSsaPssPrivateKey = Optional.empty();

    private Builder() {}

    /**
     * Sets the public key, which includes the parameters.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPublicKey(JwtRsaSsaPssPublicKey publicKey) {
      this.publicKey = Optional.of(publicKey);
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

    @CanIgnoreReturnValue
    Builder setRsaSsaPssPrivateKey(RsaSsaPssPrivateKey rsaSsaPssPrivateKey) {
      this.rsaSsaPssPrivateKey = Optional.of(rsaSsaPssPrivateKey);
      return this;
    }

    @AccessesPartialKey
    public JwtRsaSsaPssPrivateKey build() throws GeneralSecurityException {
      if (!publicKey.isPresent()) {
        throw new GeneralSecurityException("Cannot build without a RSA SSA PSS public key");
      }
      if (rsaSsaPssPrivateKey.isPresent()) {
        if (p.isPresent()
            || q.isPresent()
            || d.isPresent()
            || dP.isPresent()
            || dQ.isPresent()
            || qInv.isPresent()) {
          throw new GeneralSecurityException(
              "Cannot build with a RSA SSA PSS private key and other private key components");
        }
        if (!rsaSsaPssPrivateKey
            .get()
            .getPublicKey()
            .equalsKey(publicKey.get().getRsaSsaPssPublicKey())) {
          throw new GeneralSecurityException("public key does not match the private key");
        }
        return new JwtRsaSsaPssPrivateKey(publicKey.get(), rsaSsaPssPrivateKey.get());
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
      return new JwtRsaSsaPssPrivateKey(
          publicKey.get(),
          RsaSsaPssPrivateKey.builder()
              .setPublicKey(publicKey.get().getRsaSsaPssPublicKey())
              .setPrimes(p.get(), q.get())
              .setPrivateExponent(d.get())
              .setPrimeExponents(dP.get(), dQ.get())
              .setCrtCoefficient(qInv.get())
              .build());
    }
  }

  private JwtRsaSsaPssPrivateKey(
      JwtRsaSsaPssPublicKey publicKey, RsaSsaPssPrivateKey rsaSsaPssPrivateKey) {
    this.publicKey = publicKey;
    this.rsaSsaPssPrivateKey = rsaSsaPssPrivateKey;
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
  public JwtRsaSsaPssParameters getParameters() {
    return publicKey.getParameters();
  }

  /** Returns the public key. */
  @Override
  public JwtRsaSsaPssPublicKey getPublicKey() {
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
    return rsaSsaPssPrivateKey.getPrimeP();
  }

  /** Returns the prime factor q. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public SecretBigInteger getPrimeQ() {
    return rsaSsaPssPrivateKey.getPrimeQ();
  }

  /** Returns the private exponent d. */
  @AccessesPartialKey
  public SecretBigInteger getPrivateExponent() {
    return rsaSsaPssPrivateKey.getPrivateExponent();
  }

  /** Returns the prime exponent dP. */
  @AccessesPartialKey
  public SecretBigInteger getPrimeExponentP() {
    return rsaSsaPssPrivateKey.getPrimeExponentP();
  }

  /** Returns the prime exponent dQ. */
  @AccessesPartialKey
  public SecretBigInteger getPrimeExponentQ() {
    return rsaSsaPssPrivateKey.getPrimeExponentQ();
  }

  /** Returns the CRT coefficient qInv. */
  @AccessesPartialKey
  public SecretBigInteger getCrtCoefficient() {
    return rsaSsaPssPrivateKey.getCrtCoefficient();
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtRsaSsaPssPrivateKey)) {
      return false;
    }
    JwtRsaSsaPssPrivateKey that = (JwtRsaSsaPssPrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && that.rsaSsaPssPrivateKey.equalsKey(rsaSsaPssPrivateKey);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  RsaSsaPssPrivateKey getRsaSsaPssPrivateKey() {
    return rsaSsaPssPrivateKey;
  }
}
