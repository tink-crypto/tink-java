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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.JsonParser;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.Bytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/**
 * Provides functions to import and export public Json Web Key (JWK) sets for normal (non-JWT)
 * signature keys.
 *
 * <p>The currently supported algorithms are ES256, ES384, ES512, EdDSA, RS256, RS384, RS512, PS256,
 * PS384 and PS512.
 *
 * <p>Only keys with {@code NO_PREFIX} variant are supported for export. All imported keys will have
 * {@code NO_PREFIX} variant, and the {@code kid} field in the JWK will be ignored.
 */
public final class SignatureJwkSetConverter {

  /**
   * Converts a Tink KeysetHandle with public signature keys into a Json Web Key (JWK) set.
   *
   * <p>Only keys with {@code NO_PREFIX} variant are supported. For other variants, a {@link
   * GeneralSecurityException} is thrown.
   */
  public static String fromPublicKeysetHandle(KeysetHandle handle) throws GeneralSecurityException {
    // Check validity of the keyset handle before calling "getAt".
    // See comments in {@link KeysetHandle#Entry#getAt}.
    handle = KeysetHandle.newBuilder(handle).build();
    JsonArray keys = new JsonArray();
    for (int i = 0; i < handle.size(); i++) {
      KeysetHandle.Entry entry = handle.getAt(i);
      if (entry.getStatus() != KeyStatus.ENABLED) {
        continue;
      }
      Key key = entry.getKey();
      if (key instanceof EcdsaPublicKey) {
        keys.add(convertEcdsaKey((EcdsaPublicKey) key));
      } else if (key instanceof Ed25519PublicKey) {
        keys.add(convertEd25519Key((Ed25519PublicKey) key));
      } else if (key instanceof RsaSsaPkcs1PublicKey) {
        keys.add(convertRsaSsaPkcs1Key((RsaSsaPkcs1PublicKey) key));
      } else if (key instanceof RsaSsaPssPublicKey) {
        keys.add(convertRsaSsaPssKey((RsaSsaPssPublicKey) key));
      } else {
        throw new GeneralSecurityException(
            "unsupported key with parameters " + key.getParameters());
      }
    }
    JsonObject jwkSet = new JsonObject();
    jwkSet.add("keys", keys);
    return jwkSet.toString();
  }

  /**
   * Converts a Json Web Key (JWK) set with public keys into a Tink KeysetHandle.
   *
   * <p>All imported keys will have {@code NO_PREFIX} variant. The {@code kid} field in the JWK (if
   * present) will be ignored.
   */
  public static KeysetHandle toPublicKeysetHandle(String jwkSet) throws GeneralSecurityException {
    JsonObject jsonKeyset;
    try {
      jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    } catch (IllegalStateException | IOException ex) {
      throw new GeneralSecurityException("JWK set is invalid JSON", ex);
    }
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    for (JsonElement element : jsonKeys) {
      JsonObject jsonKey = element.getAsJsonObject();
      String kty = getStringItem(jsonKey, "kty");
      switch (kty) {
        case "EC":
          builder.addEntry(KeysetHandle.importKey(convertToEcdsaKey(jsonKey)).withRandomId());
          break;
        case "OKP":
          builder.addEntry(KeysetHandle.importKey(convertToEd25519Key(jsonKey)).withRandomId());
          break;
        case "RSA":
          String alg = getStringItem(jsonKey, "alg");
          if (alg.startsWith("RS")) {
            builder.addEntry(
                KeysetHandle.importKey(convertToRsaSsaPkcs1Key(jsonKey)).withRandomId());
          } else if (alg.startsWith("PS")) {
            builder.addEntry(KeysetHandle.importKey(convertToRsaSsaPssKey(jsonKey)).withRandomId());
          } else {
            throw new GeneralSecurityException("unexpected alg value for RSA key: " + alg);
          }
          break;
        default:
          throw new GeneralSecurityException("unexpected kty value: " + kty);
      }
    }
    if (builder.size() <= 0) {
      throw new GeneralSecurityException("empty keyset");
    }
    builder.getAt(0).makePrimary();
    return builder.build();
  }

  @AccessesPartialKey
  private static JsonObject convertEcdsaKey(EcdsaPublicKey key) throws GeneralSecurityException {
    if (key.getParameters().getVariant() != EcdsaParameters.Variant.NO_PREFIX) {
      throw new GeneralSecurityException("only keys with NO_PREFIX can be exported");
    }
    if (key.getParameters().getSignatureEncoding()
        != EcdsaParameters.SignatureEncoding.IEEE_P1363) {
      throw new GeneralSecurityException("only keys with IEEE_P1363 encoding can be exported");
    }
    String alg;
    String crv;
    int encLength;
    EcdsaParameters.CurveType curve = key.getParameters().getCurveType();
    EcdsaParameters.HashType hash = key.getParameters().getHashType();
    if (curve.equals(EcdsaParameters.CurveType.NIST_P256)) {
      if (!hash.equals(EcdsaParameters.HashType.SHA256)) {
        throw new GeneralSecurityException("NIST_P256 curve requires SHA256 hash");
      }
      alg = "ES256";
      crv = "P-256";
      encLength = 32;
    } else if (curve.equals(EcdsaParameters.CurveType.NIST_P384)) {
      if (!hash.equals(EcdsaParameters.HashType.SHA384)) {
        throw new GeneralSecurityException("NIST_P384 curve requires SHA384 hash");
      }
      alg = "ES384";
      crv = "P-384";
      encLength = 48;
    } else if (curve.equals(EcdsaParameters.CurveType.NIST_P521)) {
      if (!hash.equals(EcdsaParameters.HashType.SHA512)) {
        throw new GeneralSecurityException("NIST_P521 curve requires SHA512 hash");
      }
      alg = "ES512";
      crv = "P-521";
      encLength = 66;
    } else {
      throw new GeneralSecurityException("unknown curve type");
    }
    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "EC");
    jsonKey.addProperty("crv", crv);
    BigInteger x = key.getPublicPoint().getAffineX();
    BigInteger y = key.getPublicPoint().getAffineY();
    jsonKey.addProperty(
        "x", Base64.urlSafeEncode(BigIntegerEncoding.toBigEndianBytesOfFixedLength(x, encLength)));
    jsonKey.addProperty(
        "y", Base64.urlSafeEncode(BigIntegerEncoding.toBigEndianBytesOfFixedLength(y, encLength)));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    return jsonKey;
  }

  @AccessesPartialKey
  private static JsonObject convertEd25519Key(Ed25519PublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getVariant() != Ed25519Parameters.Variant.NO_PREFIX) {
      throw new GeneralSecurityException("only keys with NO_PREFIX can be exported");
    }
    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "OKP");
    jsonKey.addProperty("crv", "Ed25519");
    jsonKey.addProperty("x", Base64.urlSafeEncode(key.getPublicKeyBytes().toByteArray()));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", "EdDSA");
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    return jsonKey;
  }

  private static byte[] base64urlUInt(BigInteger n) {
    if (n.equals(BigInteger.ZERO)) {
      return new byte[] {0};
    }
    return BigIntegerEncoding.toUnsignedBigEndianBytes(n);
  }

  @AccessesPartialKey
  private static JsonObject convertRsaSsaPkcs1Key(RsaSsaPkcs1PublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getVariant() != RsaSsaPkcs1Parameters.Variant.NO_PREFIX) {
      throw new GeneralSecurityException("only keys with NO_PREFIX can be exported");
    }
    String alg;
    RsaSsaPkcs1Parameters.HashType hash = key.getParameters().getHashType();
    if (hash.equals(RsaSsaPkcs1Parameters.HashType.SHA256)) {
      alg = "RS256";
    } else if (hash.equals(RsaSsaPkcs1Parameters.HashType.SHA384)) {
      alg = "RS384";
    } else if (hash.equals(RsaSsaPkcs1Parameters.HashType.SHA512)) {
      alg = "RS512";
    } else {
      throw new GeneralSecurityException("unknown hash type");
    }

    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "RSA");
    jsonKey.addProperty("n", Base64.urlSafeEncode(base64urlUInt(key.getModulus())));
    jsonKey.addProperty(
        "e", Base64.urlSafeEncode(base64urlUInt(key.getParameters().getPublicExponent())));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    return jsonKey;
  }

  @AccessesPartialKey
  private static JsonObject convertRsaSsaPssKey(RsaSsaPssPublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getVariant() != RsaSsaPssParameters.Variant.NO_PREFIX) {
      throw new GeneralSecurityException("only keys with NO_PREFIX can be exported");
    }
    String alg;
    int expectedSaltLength;
    RsaSsaPssParameters.HashType hash = key.getParameters().getSigHashType();
    if (hash.equals(RsaSsaPssParameters.HashType.SHA256)) {
      alg = "PS256";
      expectedSaltLength = 32;
    } else if (hash.equals(RsaSsaPssParameters.HashType.SHA384)) {
      alg = "PS384";
      expectedSaltLength = 48;
    } else if (hash.equals(RsaSsaPssParameters.HashType.SHA512)) {
      alg = "PS512";
      expectedSaltLength = 64;
    } else {
      throw new GeneralSecurityException("unknown hash type");
    }
    if (key.getParameters().getSaltLengthBytes() != expectedSaltLength) {
      throw new GeneralSecurityException(
          "only keys with salt length matching hash length can be exported");
    }

    JsonObject jsonKey = new JsonObject();
    jsonKey.addProperty("kty", "RSA");
    jsonKey.addProperty("n", Base64.urlSafeEncode(base64urlUInt(key.getModulus())));
    jsonKey.addProperty(
        "e", Base64.urlSafeEncode(base64urlUInt(key.getParameters().getPublicExponent())));
    jsonKey.addProperty("use", "sig");
    jsonKey.addProperty("alg", alg);
    JsonArray keyOps = new JsonArray();
    keyOps.add("verify");
    jsonKey.add("key_ops", keyOps);
    return jsonKey;
  }

  @AccessesPartialKey
  private static EcdsaPublicKey convertToEcdsaKey(JsonObject jsonKey)
      throws GeneralSecurityException {
    EcdsaParameters.CurveType curveType;
    EcdsaParameters.HashType hashType;
    switch (getStringItem(jsonKey, "alg")) {
      case "ES256":
        expectStringItem(jsonKey, "crv", "P-256");
        curveType = EcdsaParameters.CurveType.NIST_P256;
        hashType = EcdsaParameters.HashType.SHA256;
        break;
      case "ES384":
        expectStringItem(jsonKey, "crv", "P-384");
        curveType = EcdsaParameters.CurveType.NIST_P384;
        hashType = EcdsaParameters.HashType.SHA384;
        break;
      case "ES512":
        expectStringItem(jsonKey, "crv", "P-521");
        curveType = EcdsaParameters.CurveType.NIST_P521;
        hashType = EcdsaParameters.HashType.SHA512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown Ecdsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("d")) {
      throw new UnsupportedOperationException("importing ECDSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "EC");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger x = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "x")));
    BigInteger y = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "y")));
    ECPoint publicPoint = new ECPoint(x, y);

    return EcdsaPublicKey.builder()
        .setParameters(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setCurveType(curveType)
                .setHashType(hashType)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build())
        .setPublicPoint(publicPoint)
        .build();
  }

  @AccessesPartialKey
  private static Ed25519PublicKey convertToEd25519Key(JsonObject jsonKey)
      throws GeneralSecurityException {
    expectStringItem(jsonKey, "kty", "OKP");
    expectStringItem(jsonKey, "alg", "EdDSA");
    expectStringItem(jsonKey, "crv", "Ed25519");
    if (jsonKey.has("d")) {
      throw new UnsupportedOperationException("importing EdDSA private keys is not implemented");
    }
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    byte[] keyBytes = Base64.urlSafeDecode(getStringItem(jsonKey, "x"));
    return Ed25519PublicKey.create(
        Ed25519Parameters.Variant.NO_PREFIX, Bytes.copyFrom(keyBytes), /* idRequirement= */ null);
  }

  @AccessesPartialKey
  private static RsaSsaPkcs1PublicKey convertToRsaSsaPkcs1Key(JsonObject jsonKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters.HashType hashType;
    switch (getStringItem(jsonKey, "alg")) {
      case "RS256":
        hashType = RsaSsaPkcs1Parameters.HashType.SHA256;
        break;
      case "RS384":
        hashType = RsaSsaPkcs1Parameters.HashType.SHA384;
        break;
      case "RS512":
        hashType = RsaSsaPkcs1Parameters.HashType.SHA512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown RSA PKCS1 Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dp")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger publicExponent =
        new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "e")));
    BigInteger modulus = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "n")));

    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(modulus.bitLength())
                .setPublicExponent(publicExponent)
                .setHashType(hashType)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build())
        .setModulus(modulus)
        .build();
  }

  @AccessesPartialKey
  private static RsaSsaPssPublicKey convertToRsaSsaPssKey(JsonObject jsonKey)
      throws GeneralSecurityException {
    RsaSsaPssParameters.HashType hashType;
    switch (getStringItem(jsonKey, "alg")) {
      case "PS256":
        hashType = RsaSsaPssParameters.HashType.SHA256;
        break;
      case "PS384":
        hashType = RsaSsaPssParameters.HashType.SHA384;
        break;
      case "PS512":
        hashType = RsaSsaPssParameters.HashType.SHA512;
        break;
      default:
        throw new GeneralSecurityException(
            "Unknown RSA PSS Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dp")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);

    BigInteger publicExponent =
        new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "e")));
    BigInteger modulus = new BigInteger(1, Base64.urlSafeDecode(getStringItem(jsonKey, "n")));

    int saltLength;
    if (hashType.equals(RsaSsaPssParameters.HashType.SHA256)) {
      saltLength = 32;
    } else if (hashType.equals(RsaSsaPssParameters.HashType.SHA384)) {
      saltLength = 48;
    } else if (hashType.equals(RsaSsaPssParameters.HashType.SHA512)) {
      saltLength = 64;
    } else {
      throw new GeneralSecurityException("unknown hash type");
    }

    return RsaSsaPssPublicKey.builder()
        .setParameters(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(modulus.bitLength())
                .setPublicExponent(publicExponent)
                .setSigHashType(hashType)
                .setMgf1HashType(hashType)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(saltLength)
                .build())
        .setModulus(modulus)
        .build();
  }

  private static String getStringItem(JsonObject obj, String name) throws GeneralSecurityException {
    if (!obj.has(name)) {
      throw new GeneralSecurityException(name + " not found");
    }
    if (!obj.get(name).isJsonPrimitive() || !obj.get(name).getAsJsonPrimitive().isString()) {
      throw new GeneralSecurityException(name + " is not a string");
    }
    return obj.get(name).getAsString();
  }

  private static void expectStringItem(JsonObject obj, String name, String expectedValue)
      throws GeneralSecurityException {
    String value = getStringItem(obj, name);
    if (!value.equals(expectedValue)) {
      throw new GeneralSecurityException("unexpected " + name + " value: " + value);
    }
  }

  private static void validateUseIsSig(JsonObject jsonKey) throws GeneralSecurityException {
    if (!jsonKey.has("use")) {
      return;
    }
    expectStringItem(jsonKey, "use", "sig");
  }

  private static void validateKeyOpsIsVerify(JsonObject jsonKey) throws GeneralSecurityException {
    if (!jsonKey.has("key_ops")) {
      return;
    }
    if (!jsonKey.get("key_ops").isJsonArray()) {
      throw new GeneralSecurityException("key_ops is not an array");
    }
    JsonArray keyOps = jsonKey.get("key_ops").getAsJsonArray();
    if (keyOps.size() != 1) {
      throw new GeneralSecurityException("key_ops must contain exactly one element");
    }
    if (!keyOps.get(0).isJsonPrimitive() || !keyOps.get(0).getAsJsonPrimitive().isString()) {
      throw new GeneralSecurityException("key_ops is not a string");
    }
    if (!keyOps.get(0).getAsString().equals("verify")) {
      throw new GeneralSecurityException("unexpected keyOps value: " + keyOps.get(0).getAsString());
    }
  }

  private SignatureJwkSetConverter() {}
}
