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

import static com.google.common.truth.Truth.assertWithMessage;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for JwtConfig2026 which run under fips mode.
 *
 * <p>We test this by tagging the test with "fips" which will run it three configurations: *
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=False,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True and BORINGSSL_FIPS=0 in C++.`
 */
@RunWith(JUnit4.class)
@AccessesPartialKey
public class JwtConfig2026FipsTest {

  private static final ECPoint P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);

  private static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                  + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                  + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                  + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                  + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                  + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"));
  private static final BigInteger P =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                  + "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                  + "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"));
  private static final BigInteger Q =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                  + "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                  + "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"));
  private static final BigInteger D =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                  + "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                  + "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                  + "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                  + "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                  + "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"));
  private static final BigInteger DP =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                  + "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                  + "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"));
  private static final BigInteger DQ =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                  + "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                  + "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"));
  private static final BigInteger Q_INV =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                  + "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                  + "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"));

  @BeforeClass
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Nullable
  private static JwtHmacKey createHmacKeyOrNull() {
    try {
      JwtHmacParameters parameters =
          JwtHmacParameters.builder()
              .setKeySizeBytes(32)
              .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
              .build();
      return JwtHmacKey.builder()
          .setParameters(parameters)
          .setKeyBytes(SecretBytes.randomBytes(32))
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createEcdsaPrivateKeyOrNull() {
    try {
      JwtEcdsaParameters parameters =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JwtEcdsaPublicKey publicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(parameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .build();
      return JwtEcdsaPrivateKey.create(
          publicKey,
          SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createRsaSsaPkcs1PrivateKey2048BitOrNull() {
    try {
      JwtRsaSsaPkcs1Parameters parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey publicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(parameters)
              .setModulus(MODULUS)
              .build();
      RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey =
          RsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(publicKey.getRsaSsaPkcs1PublicKey())
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();
      return JwtRsaSsaPkcs1PrivateKey.builder()
          .setPublicKey(publicKey)
          .setRsaSsaPkcs1PrivateKey(rsaSsaPkcs1PrivateKey)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createRsaSsaPkcs1PrivateKey4096BitOrNull() {
    try {
      RsaSsaPkcs1Parameters rawParameters =
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(RsaSsaPkcs1Parameters.F4)
              .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .build();
      RsaSsaPkcs1PrivateKey rawKey =
          RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(rawParameters, null);
      JwtRsaSsaPkcs1Parameters parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey publicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(parameters)
              .setModulus(rawKey.getPublicKey().getModulus())
              .build();
      return JwtRsaSsaPkcs1PrivateKey.builder()
          .setPublicKey(publicKey)
          .setRsaSsaPkcs1PrivateKey(rawKey)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createRsaSsaPssPrivateKey2048BitOrNull() {
    try {
      JwtRsaSsaPssParameters parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey publicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(parameters)
              .setModulus(MODULUS)
              .build();
      RsaSsaPssPrivateKey rsaSsaPssPrivateKey =
          RsaSsaPssPrivateKey.builder()
              .setPublicKey(publicKey.getRsaSsaPssPublicKey())
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();
      return JwtRsaSsaPssPrivateKey.builder()
          .setPublicKey(publicKey)
          .setRsaSsaPssPrivateKey(rsaSsaPssPrivateKey)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createRsaSsaPssPrivateKey4096BitOrNull() {
    try {
      RsaSsaPssParameters rawParameters =
          RsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(RsaSsaPssParameters.F4)
              .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
              .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
              .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
              .setSaltLengthBytes(32)
              .build();
      RsaSsaPssPrivateKey rawKey =
          RsaSsaPssTestUtil.privateKeyFor4096BitParameters(rawParameters, null);
      JwtRsaSsaPssParameters parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey publicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(parameters)
              .setModulus(rawKey.getPublicKey().getModulus())
              .build();
      return JwtRsaSsaPssPrivateKey.builder()
          .setPublicKey(publicKey)
          .setRsaSsaPssPrivateKey(rawKey)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static JwtSignaturePrivateKey createMlDsaPrivateKeyOrNull() {
    try {
      MlDsaPrivateKey mlDsa44PrivateKey =
          (MlDsaPrivateKey)
              MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                      MlDsaParameters.create(
                          MlDsaParameters.MlDsaInstance.ML_DSA_44,
                          MlDsaParameters.Variant.NO_PREFIX))
                  .getPrivateKey();
      JwtMlDsaParameters parameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
      JwtMlDsaPublicKey publicKey =
          JwtMlDsaPublicKey.builder()
              .setParameters(parameters)
              .setPublicKeyBytes(mlDsa44PrivateKey.getPublicKey().getSerializedPublicKey())
              .build();
      return JwtMlDsaPrivateKey.create(publicKey, mlDsa44PrivateKey.getPrivateSeed());
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  /**
   * Returns HMAC keys which should work.
   *
   * <p>If `use_only_fips=False` then this is all HMAC keys. If `use_only_fips=True` and BoringSSL
   * was compiled with `BORINGSSL_FIPS` then these are the FIPS HMAC keys in BoringSSL. If
   * `use_only_fips=True` and `BORINGSSL_FIPS=0` then this is the empty list.
   */
  private static List<JwtHmacKey> createHmacKeysWhichShouldWork() {
    ArrayList<JwtHmacKey> result = new ArrayList<>();
    if (TinkFipsUtil.fipsModuleAvailable() || !TinkFipsUtil.useOnlyFips()) {
      result.add(createHmacKeyOrNull());
    }
    for (int i = 0; i < result.size(); i++) {
      assertWithMessage("Position %s is null", i).that(result.get(i)).isNotNull();
    }
    return result;
  }

  /** Returns HMAC keys which should fail. */
  private static List<JwtHmacKey> createHmacKeysWhichShouldFail() {
    ArrayList<JwtHmacKey> result = new ArrayList<>();
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      JwtHmacKey hmacKey = createHmacKeyOrNull();
      if (hmacKey != null) {
        result.add(hmacKey);
      }
    }
    return result;
  }

  /**
   * Returns Signature keys which should work.
   *
   * <p>If `use_only_fips=False` then this is all keys. If `use_only_fips=True` and BoringSSL was
   * compiled with `BORINGSSL_FIPS` then these are the FIPS keys in BoringSSL. If `use_only_fips=True`
   * and `BORINGSSL_FIPS=0` then this is the empty list.
   */
  private static List<JwtSignaturePrivateKey> createSignatureKeysWhichShouldWork() {
    ArrayList<JwtSignaturePrivateKey> result = new ArrayList<>();
    if (TinkFipsUtil.fipsModuleAvailable() || !TinkFipsUtil.useOnlyFips()) {
      result.add(createEcdsaPrivateKeyOrNull());
      result.add(createRsaSsaPkcs1PrivateKey2048BitOrNull());
      result.add(createRsaSsaPssPrivateKey2048BitOrNull());
    }

    if (!TinkFipsUtil.useOnlyFips()) {
      result.add(createMlDsaPrivateKeyOrNull());
      result.add(createRsaSsaPkcs1PrivateKey4096BitOrNull());
      result.add(createRsaSsaPssPrivateKey4096BitOrNull());
    }
    for (int i = 0; i < result.size(); i++) {
      assertWithMessage("Position %s is null", i).that(result.get(i)).isNotNull();
    }
    return result;
  }

  /** Returns Signature keys which should fail. */
  private static List<JwtSignaturePrivateKey> createSignatureKeysWhichShouldFail() {
    ArrayList<JwtSignaturePrivateKey> result = new ArrayList<>();
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      JwtSignaturePrivateKey ecdsaKey = createEcdsaPrivateKeyOrNull();
      if (ecdsaKey != null) {
        result.add(ecdsaKey);
      }
      JwtSignaturePrivateKey rsaPkcs1Key = createRsaSsaPkcs1PrivateKey2048BitOrNull();
      if (rsaPkcs1Key != null) {
        result.add(rsaPkcs1Key);
      }
      JwtSignaturePrivateKey rsaPssKey = createRsaSsaPssPrivateKey2048BitOrNull();
      if (rsaPssKey != null) {
        result.add(rsaPssKey);
      }
    }

    if (TinkFipsUtil.useOnlyFips()) {
      JwtSignaturePrivateKey mlDsaKey = createMlDsaPrivateKeyOrNull();
      if (mlDsaKey != null) {
        result.add(mlDsaKey);
      }
      JwtSignaturePrivateKey rsaPkcs1Key4096 = createRsaSsaPkcs1PrivateKey4096BitOrNull();
      if (rsaPkcs1Key4096 != null) {
        result.add(rsaPkcs1Key4096);
      }
      JwtSignaturePrivateKey rsaPssKey4096 = createRsaSsaPssPrivateKey4096BitOrNull();
      if (rsaPssKey4096 != null) {
        result.add(rsaPssKey4096);
      }
    }
    return result;
  }

  @Test
  public void getPrimitive_jwtMac_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      JwtMac mac = handle.getPrimitive(JwtConfig2026.get(), JwtMac.class);
      JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
      RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
      String compact = mac.computeMacAndEncode(rawToken);
      VerifiedJwt verifiedToken = mac.verifyMacAndDecode(compact, validator);
      assertWithMessage("Failed for key: %s", key)
          .that(verifiedToken.getJwtId())
          .isEqualTo("jwtId");
    }
  }

  @Test
  public void getPrimitive_signVerify_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
      KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

      JwtPublicKeySign signer = handle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class);
      JwtPublicKeyVerify verifier =
          publicKeyHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class);
      JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
      RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
      String signedCompact = signer.signAndEncode(rawToken);
      VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
      assertWithMessage("Failed for key: %s", key)
          .that(verifiedToken.getJwtId())
          .isEqualTo("jwtId");
    }
  }

  @Test
  public void serializeAndParseHmacKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = JwtConfig2026.get();
      byte[] serialized =
          TinkProtoKeysetFormat.serializeKeyset(
              keysetHandle, InsecureSecretKeyAccess.get(), config);
      KeysetHandle parsed =
          TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

      assertWithMessage("Failed for key: %s", key).that(parsed.equalsKeyset(keysetHandle)).isTrue();
    }
  }

  @Test
  public void serializeAndParsePrivateKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = JwtConfig2026.get();
      byte[] serialized =
          TinkProtoKeysetFormat.serializeKeyset(
              keysetHandle, InsecureSecretKeyAccess.get(), config);
      KeysetHandle parsed =
          TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

      assertWithMessage("Failed for key: %s", key).that(parsed.equalsKeyset(keysetHandle)).isTrue();
    }
  }

  @Test
  public void serializeAndParsePublicKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldWork()) {
      JwtSignaturePublicKey publicKey = key.getPublicKey();
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(publicKey).makePrimary();
      if (publicKey.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(publicKey.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = JwtConfig2026.get();
      byte[] serialized = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, config);
      KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed.equalsKeyset(keysetHandle)).isTrue();
    }
  }

  @Test
  public void serializeAndParseParameters_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldWork()) {
      Parameters parameters = key.getParameters();
      Configuration config = JwtConfig2026.get();
      byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
      Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed).isEqualTo(parameters);
    }
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldWork()) {
      Parameters parameters = key.getParameters();
      Configuration config = JwtConfig2026.get();
      byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
      Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed).isEqualTo(parameters);
    }
  }

  @Test
  public void createKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldWork()) {
      Configuration config = JwtConfig2026.get();

      KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

      assertWithMessage("Failed for key: %s", key)
          .that(handle.getPrimary().getKey().getParameters())
          .isEqualTo(key.getParameters());
    }
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldWork()) {
      Configuration config = JwtConfig2026.get();

      KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

      assertWithMessage("Failed for key: %s", key)
          .that(handle.getPrimary().getKey().getParameters())
          .isEqualTo(key.getParameters());
    }
  }

  @Test
  public void getPrimitive_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldFail()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration configuration = JwtConfig2026.get();
      assertThrows(
          "Expected getPrimitive(JwtMac) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, JwtMac.class));
    }
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldFail()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
      KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

      Configuration configuration = JwtConfig2026.get();
      assertThrows(
          "Expected getPrimitive(JwtPublicKeySign) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, JwtPublicKeySign.class));
      assertThrows(
          "Expected getPrimitive(JwtPublicKeyVerify) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> publicKeyHandle.getPrimitive(configuration, JwtPublicKeyVerify.class));
    }
  }

  @Test
  public void createKey_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (JwtHmacKey key : createHmacKeysWhichShouldFail()) {
      Configuration config = JwtConfig2026.get();

      assertThrows(
          "Expected generateNew to throw for key: " + key,
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
    }
    for (JwtSignaturePrivateKey key : createSignatureKeysWhichShouldFail()) {
      Configuration config = JwtConfig2026.get();

      assertThrows(
          "Expected generateNew to throw for key: " + key,
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
    }
  }

  // Note: we do not check parse/serialize for Non-FIPS keys -- we are fine with either behavior.
}
