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

package com.google.crypto.tink.jwt.internal.testing;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.crypto.tink.jwt.JwtSignaturePrivateKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Utility fot testing Jwt signing algorithms. */
@AccessesPartialKey
public final class JwtSignatureTestUtil {

  public static final String CUSTOM_KID_VALUE =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
  private static final ECPoint P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);
  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.7
  private static final ECPoint P521_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                  + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                  + "3A4",
              16),
          new BigInteger(
              "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                  + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                  + "CF5",
              16));
  private static final BigInteger P521_PRIVATE_VALUE =
      new BigInteger(
          "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
              + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
              + "538",
          16);
  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.6
  private static final ECPoint P384_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
              16),
          new BigInteger(
              "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
              16));
  private static final BigInteger P384_PRIVATE_VALUE =
      new BigInteger(
          "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
          16);

  private static final JwtEcdsaParameters JWT_ECDSA_ES256_RAW_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES256_RAW_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES256_RAW_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES256_RAW_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JWT_ECDSA_ES256_RAW_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES256_RAW_PARAMETERS)
              .setPublicPoint(P256_PUBLIC_POINT)
              .build();
      JWT_ECDSA_ES256_RAW_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES256_RAW_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES256_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES256_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES256_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES256_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JWT_ECDSA_ES256_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES256_PARAMETERS)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JWT_ECDSA_ES256_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES256_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES256_CUSTOM_KID_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES256_CUSTOM_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES256_CUSTOM_KID_PRIVATE_KEY;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES256_WRONG_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES256_WRONG_KID_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES256_CUSTOM_KID_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JWT_ECDSA_ES256_CUSTOM_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES256_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JWT_ECDSA_ES256_CUSTOM_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES256_CUSTOM_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JWT_ECDSA_ES256_WRONG_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES256_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JWT_ECDSA_ES256_WRONG_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES256_WRONG_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES512_RAW_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES512_RAW_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES512_RAW_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES512_RAW_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JWT_ECDSA_ES512_RAW_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES512_RAW_PARAMETERS)
              .setPublicPoint(P521_PUBLIC_POINT)
              .build();
      JWT_ECDSA_ES512_RAW_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES512_RAW_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES512_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES512_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES512_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES512_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JWT_ECDSA_ES512_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES512_PARAMETERS)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JWT_ECDSA_ES512_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES512_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES512_CUSTOM_KID_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES512_CUSTOM_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES512_CUSTOM_KID_PRIVATE_KEY;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES512_WRONG_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES512_WRONG_KID_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES512_CUSTOM_KID_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JWT_ECDSA_ES512_CUSTOM_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES512_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JWT_ECDSA_ES512_CUSTOM_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES512_CUSTOM_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JWT_ECDSA_ES512_WRONG_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES512_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JWT_ECDSA_ES512_WRONG_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES512_WRONG_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES384_RAW_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES384_RAW_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES384_RAW_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES384_RAW_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JWT_ECDSA_ES384_RAW_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES384_RAW_PARAMETERS)
              .setPublicPoint(P384_PUBLIC_POINT)
              .build();
      JWT_ECDSA_ES384_RAW_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES384_RAW_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES384_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES384_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES384_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES384_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JWT_ECDSA_ES384_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES384_PARAMETERS)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JWT_ECDSA_ES384_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES384_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final JwtEcdsaParameters JWT_ECDSA_ES384_CUSTOM_KID_PARAMETERS;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES384_CUSTOM_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES384_CUSTOM_KID_PRIVATE_KEY;
  private static final JwtEcdsaPublicKey JWT_ECDSA_ES384_WRONG_KID_PUBLIC_KEY;
  private static final JwtEcdsaPrivateKey JWT_ECDSA_ES384_WRONG_KID_PRIVATE_KEY;

  static {
    try {
      JWT_ECDSA_ES384_CUSTOM_KID_PARAMETERS =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JWT_ECDSA_ES384_CUSTOM_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES384_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JWT_ECDSA_ES384_CUSTOM_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES384_CUSTOM_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JWT_ECDSA_ES384_WRONG_KID_PUBLIC_KEY =
          JwtEcdsaPublicKey.builder()
              .setParameters(JWT_ECDSA_ES384_CUSTOM_KID_PARAMETERS)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JWT_ECDSA_ES384_WRONG_KID_PRIVATE_KEY =
          JwtEcdsaPrivateKey.create(
              JWT_ECDSA_ES384_WRONG_KID_PUBLIC_KEY,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static String generateSignedCompact(
      PublicKeySign rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature = Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  public static List<JwtSignaturePrivateKey> createJwtEcdsaPrivateKeys() {
    return Arrays.asList(
        JWT_ECDSA_ES256_RAW_PRIVATE_KEY,
        JWT_ECDSA_ES256_PRIVATE_KEY,
        JWT_ECDSA_ES384_RAW_PRIVATE_KEY,
        JWT_ECDSA_ES384_PRIVATE_KEY,
        JWT_ECDSA_ES512_RAW_PRIVATE_KEY,
        JWT_ECDSA_ES512_PRIVATE_KEY);
  }

  public static final Map<String, JwtSignaturePrivateKey> jwtRawPrivateKeyMap =
      createJwtRawPrivateKeyMap();

  private static final Map<String, JwtSignaturePrivateKey> createJwtRawPrivateKeyMap() {
    Map<String, JwtSignaturePrivateKey> result = new HashMap<>();
    result.put("ES256", JWT_ECDSA_ES256_RAW_PRIVATE_KEY);
    result.put("ES384", JWT_ECDSA_ES384_RAW_PRIVATE_KEY);
    result.put("ES512", JWT_ECDSA_ES512_RAW_PRIVATE_KEY);
    return result;
  }

  public static final Map<String, JwtSignaturePrivateKey> jwtCustomKidPrivateKeyMap =
      createJwtCustomKidPrivateKeyMap();

  private static final Map<String, JwtSignaturePrivateKey> createJwtCustomKidPrivateKeyMap() {
    Map<String, JwtSignaturePrivateKey> result = new HashMap<>();
    result.put("ES256", JWT_ECDSA_ES256_CUSTOM_KID_PRIVATE_KEY);
    result.put("ES384", JWT_ECDSA_ES384_CUSTOM_KID_PRIVATE_KEY);
    result.put("ES512", JWT_ECDSA_ES512_CUSTOM_KID_PRIVATE_KEY);
    return result;
  }

  public static final Map<String, JwtSignaturePrivateKey> jwtWrongKidPrivateKeyMap =
      createJwtWrongKidPrivateKeyMap();

  private static final Map<String, JwtSignaturePrivateKey> createJwtWrongKidPrivateKeyMap() {
    Map<String, JwtSignaturePrivateKey> result = new HashMap<>();
    result.put("ES256", JWT_ECDSA_ES256_WRONG_KID_PRIVATE_KEY);
    result.put("ES384", JWT_ECDSA_ES384_WRONG_KID_PRIVATE_KEY);
    result.put("ES512", JWT_ECDSA_ES512_WRONG_KID_PRIVATE_KEY);
    return result;
  }

  private JwtSignatureTestUtil() {}
}
