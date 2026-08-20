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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/** Utility methods for ASN.1 encoding. */
public final class Asn1Util {
  private static final byte TAG_INTEGER = 0x02;
  private static final byte TAG_SEQUENCE = 0x30;
  private static final byte TAG_OCTET_STRING = 0x04;
  private static final byte TAG_NULL = 0x05;
  private static final byte TAG_OBJECT_IDENTIFIER = 0x06;
  private static final byte NULL_BYTE = 0x00;

  private static final byte[] versionZero = new byte[] {TAG_INTEGER, 0x01, 0x00};
  private static final byte[] rsaEncryptionOid =
      new byte[] {
        TAG_SEQUENCE,
        0x0d,
        TAG_OBJECT_IDENTIFIER,
        0x09,
        0x2a,
        (byte) 0x86,
        0x48,
        (byte) 0x86,
        (byte) 0xf7,
        0x0d,
        0x01,
        0x01,
        0x01,
        TAG_NULL,
        NULL_BYTE
      };

  private Asn1Util() {}

  private static byte[] createInteger(BigInteger val) {
    byte[] bytes = val.toByteArray();
    byte[] lengthField = createLength(bytes.length);
    byte[] result = new byte[1 + lengthField.length + bytes.length];

    result[0] = TAG_INTEGER;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    System.arraycopy(bytes, 0, result, 1 + lengthField.length, bytes.length);
    return result;
  }

  private static byte[] createLength(int length) {
    if (length <= 127) {
      return new byte[] {(byte) length};
    }

    int temp = length;
    int numBytes = 0;
    while (temp > 0) {
      numBytes++;
      temp >>= 8;
    }

    byte[] result = new byte[1 + numBytes];
    result[0] = (byte) (0x80 | numBytes);
    for (int i = numBytes; i > 0; i--) {
      result[i] = (byte) (length & 0xFF);
      length >>= 8;
    }
    return result;
  }

  private static byte[] createSequence(List<byte[]> elements) {
    int totalLength = 0;
    for (byte[] el : elements) {
      totalLength += el.length;
    }
    byte[] lengthField = createLength(totalLength);
    byte[] result = new byte[1 + lengthField.length + totalLength];

    result[0] = TAG_SEQUENCE;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    int offset = 1 + lengthField.length;
    for (byte[] el : elements) {
      System.arraycopy(el, 0, result, offset, el.length);
      offset += el.length;
    }
    return result;
  }
  
  private static byte[] createOctetString(byte[] value) {
    byte[] lengthField = createLength(value.length);
    byte[] result = new byte[1 + lengthField.length + value.length];
    result[0] = TAG_OCTET_STRING;
    System.arraycopy(lengthField, 0, result, 1, lengthField.length);
    System.arraycopy(value, 0, result, 1 + lengthField.length, value.length);
    return result;
  }

  /**
   * Takes a Tink RsaSsaPssPrivateKey and returns the ASN.1 encoded PKCS#1 private key as per
   * https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.2:
   *
   * <pre>{@code
   * RSAPrivateKey ::= SEQUENCE {
   *   version           Version,
   *   modulus           INTEGER,  -- n
   *   publicExponent    INTEGER,  -- e
   *   privateExponent   INTEGER,  -- d
   *   prime1            INTEGER,  -- p
   *   prime2            INTEGER,  -- q
   *   exponent1         INTEGER,  -- d mod (p-1)
   *   exponent2         INTEGER,  -- d mod (q-1)
   *   coefficient       INTEGER,  -- (inverse of q) mod p
   *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
   * }
   * }</pre>
   *
   * with version 0 and 'otherPrimeInfos' absent.
   */
  @AccessesPartialKey
  public static byte[] rsaSsaPssPrivateKeyToPkcs1Bytes(RsaSsaPssPrivateKey key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(createInteger(BigInteger.ZERO));
    elements.add(createInteger(key.getPublicKey().getModulus()));
    elements.add(createInteger(key.getPublicKey().getParameters().getPublicExponent()));
    elements.add(
        createInteger(key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(createInteger(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(createInteger(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    return createSequence(elements);
  }

  /**
   * Takes a Tink RsaSsaPkcs1PrivateKey and returns the ASN.1 encoded PKCS#1 private key as per
   * https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.2:
   *
   * <pre>{@code
   * RSAPrivateKey ::= SEQUENCE {
   *   version           Version,
   *   modulus           INTEGER,  -- n
   *   publicExponent    INTEGER,  -- e
   *   privateExponent   INTEGER,  -- d
   *   prime1            INTEGER,  -- p
   *   prime2            INTEGER,  -- q
   *   exponent1         INTEGER,  -- d mod (p-1)
   *   exponent2         INTEGER,  -- d mod (q-1)
   *   coefficient       INTEGER,  -- (inverse of q) mod p
   *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
   * }
   * }</pre>
   *
   * with version 0 and 'otherPrimeInfos' absent.
   */
  @AccessesPartialKey
  public static byte[] rsaSsaPkcs1PrivateKeyToPkcs1Bytes(RsaSsaPkcs1PrivateKey key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(createInteger(BigInteger.ZERO));
    elements.add(createInteger(key.getPublicKey().getModulus()));
    elements.add(createInteger(key.getPublicKey().getParameters().getPublicExponent()));
    elements.add(
        createInteger(key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(createInteger(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(createInteger(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get())));
    elements.add(
        createInteger(key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    return createSequence(elements);
  }

  /**
   * Takes a Tink RsaSsaPssPublicKey and returns the ASN.1 encoded PKCS#1 public key as per
   * https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.1:
   *
   * <pre>{@code
   * RSAPublicKey ::= SEQUENCE {
   *   modulus           INTEGER,  -- n
   *   publicExponent    INTEGER   -- e
   * }
   * }</pre>
   */
  @AccessesPartialKey
  public static byte[] rsaSsaPssPublicKeyToPkcs1Bytes(RsaSsaPssPublicKey key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(createInteger(key.getModulus()));
    elements.add(createInteger(key.getParameters().getPublicExponent()));
    return createSequence(elements);
  }

  /**
   * Takes a Tink RsaSsaPkcs1PublicKey and returns the ASN.1 encoded PKCS#1 public key as per
   * https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.1:
   *
   * <pre>{@code
   * RSAPublicKey ::= SEQUENCE {
   *   modulus           INTEGER,  -- n
   *   publicExponent    INTEGER   -- e
   * }
   * }</pre>
   */
  @AccessesPartialKey
  public static byte[] rsaSsaPkcs1PublicKeyToPkcs1Bytes(RsaSsaPkcs1PublicKey key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(createInteger(key.getModulus()));
    elements.add(createInteger(key.getParameters().getPublicExponent()));
    return createSequence(elements);
  }

  /**
   * Takes a PKCS#1 encoded key and returns the `OneAsymmetricKey` (a.k.a. `PrivateKeyInfo`) ASN.1
   * structure as per
   * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-asn1-definitions
   * and https://www.rfc-editor.org/info/rfc5958/#appendix-A.
   *
   * <pre>{@code
   * OneAsymmetricKey ::= SEQUENCE {
   *   version Version,
   *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
   *   privateKey PrivateKey,
   *   attributes [0] Attributes OPTIONAL,
   *   ...,
   *   [[2: publicKey [1] PublicKey OPTIONAL ]],
   *   ...
   * }
   *
   * PrivateKeyInfo ::= OneAsymmetricKey
   * }</pre>
   */
  public static byte[] createPrivateKeyInfo(byte[] pkcs1Key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(rsaEncryptionOid);
    elements.add(pkcs1Key);
    return createSequence(elements);
  }

  /**
   * Takes a PKCS#1 encoded key and returns the ASN.1 encoded PKCS#8 private key as per
   * https://datatracker.ietf.org/doc/html/rfc5208#section-5.
   *
   * PrivateKeyInfo ::= SEQUENCE {
   *   version                   Version,
   *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
   *   privateKey                PrivateKey,
   *   attributes           [0]  IMPLICIT Attributes OPTIONAL }
   *
   * <p>with version 0 and attributes absent.
   */
  public static byte[] createPkcs8RsaKeyFromPkcs1RsaKey(byte[] pkcs1Key) {
    List<byte[]> elements = new ArrayList<>();
    elements.add(versionZero);
    elements.add(rsaEncryptionOid);
    elements.add(createOctetString(pkcs1Key));
    return createSequence(elements);
  }

  /**
   * Parses a PKCS#1 encoded RSA private key and constructs a Tink {@link RsaSsaPssPrivateKey} using
   * the provided {@link RsaSsaPssParameters}.
   *
   * <p>Only allows F4 exponent.
   */
  @AccessesPartialKey
  public static RsaSsaPssPrivateKey pkcs1RsaKeyToRsaSsaPssPrivateKey(
      byte[] pkcs1Key, RsaSsaPssParameters parameters) throws GeneralSecurityException {
    BigInteger version;
    BigInteger modulus;
    BigInteger publicExponent;
    BigInteger privateExponent;
    BigInteger primeP;
    BigInteger primeQ;
    BigInteger primeExponentP;
    BigInteger primeExponentQ;
    BigInteger crtCoefficient;
    try (Asn1StatefulParser parser = new Asn1StatefulParser(pkcs1Key);
        Asn1StatefulParser sequenceParser = parser.consumeSequence()) {
      version = sequenceParser.consumeInteger();
      if (!version.equals(BigInteger.ZERO)) {
        throw new GeneralSecurityException(
            "Unsupported PKCS#1 RSA private key version: " + version);
      }
      modulus = sequenceParser.consumeInteger();
      publicExponent = sequenceParser.consumeInteger();
      privateExponent = sequenceParser.consumeInteger();
      primeP = sequenceParser.consumeInteger();
      primeQ = sequenceParser.consumeInteger();
      primeExponentP = sequenceParser.consumeInteger();
      primeExponentQ = sequenceParser.consumeInteger();
      crtCoefficient = sequenceParser.consumeInteger();
    } catch (Asn1StatefulParser.Asn1ParserException e) {
      throw new GeneralSecurityException("Failed to parse PKCS#1 RSA private key", e);
    }

    // There is no need to additionally check the public exponent in the Parameters, since the
    // Builder there only allows F4.
    if (!publicExponent.equals(RsaSsaPssParameters.F4)) {
      throw new GeneralSecurityException(
          "Unsupported public exponent for RSA key: " + publicExponent.toString(16));
    }

    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(modulus).build();
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(primeP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeQ, InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(privateExponent, InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(primeExponentP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeExponentQ, InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(crtCoefficient, InsecureSecretKeyAccess.get()))
        .build();
  }

  /**
   * Parses a PKCS#1 encoded RSA private key and constructs a Tink {@link RsaSsaPkcs1PrivateKey}
   * using the provided {@link RsaSsaPkcs1Parameters}.
   *
   * <p>Only allows F4 exponent.
   */
  @AccessesPartialKey
  public static RsaSsaPkcs1PrivateKey pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(
      byte[] pkcs1Key, RsaSsaPkcs1Parameters parameters) throws GeneralSecurityException {
    BigInteger version;
    BigInteger modulus;
    BigInteger publicExponent;
    BigInteger privateExponent;
    BigInteger primeP;
    BigInteger primeQ;
    BigInteger primeExponentP;
    BigInteger primeExponentQ;
    BigInteger crtCoefficient;
    try (Asn1StatefulParser parser = new Asn1StatefulParser(pkcs1Key);
        Asn1StatefulParser sequenceParser = parser.consumeSequence()) {
      version = sequenceParser.consumeInteger();
      if (!version.equals(BigInteger.ZERO)) {
        throw new GeneralSecurityException(
            "Unsupported PKCS#1 RSA private key version: " + version);
      }
      modulus = sequenceParser.consumeInteger();
      publicExponent = sequenceParser.consumeInteger();
      privateExponent = sequenceParser.consumeInteger();
      primeP = sequenceParser.consumeInteger();
      primeQ = sequenceParser.consumeInteger();
      primeExponentP = sequenceParser.consumeInteger();
      primeExponentQ = sequenceParser.consumeInteger();
      crtCoefficient = sequenceParser.consumeInteger();
    } catch (Asn1StatefulParser.Asn1ParserException e) {
      throw new GeneralSecurityException("Failed to parse PKCS#1 RSA private key", e);
    }

    // There is no need to additionally check the public exponent in the Parameters, since the
    // Builder there only allows F4.
    if (!publicExponent.equals(RsaSsaPkcs1Parameters.F4)) {
      throw new GeneralSecurityException(
          "Unsupported public exponent for RSA key: " + publicExponent.toString(16));
    }

    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(modulus).build();
    return RsaSsaPkcs1PrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(primeP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeQ, InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(privateExponent, InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(primeExponentP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeExponentQ, InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(crtCoefficient, InsecureSecretKeyAccess.get()))
        .build();
  }
}
