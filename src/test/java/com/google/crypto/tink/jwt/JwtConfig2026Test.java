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

import static com.google.common.truth.Truth.assertThat;

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
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.ECPoint;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link JwtConfig2026}. */
@RunWith(Theories.class)
public class JwtConfig2026Test {

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

  @AccessesPartialKey
  public static void createTestKeys() {
    try {
      JwtHmacParameters jwtHmacParameters =
          JwtHmacParameters.builder()
              .setKeySizeBytes(32)
              .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
              .build();
      JwtHmacKey jwtHmacKey =
          JwtHmacKey.builder()
              .setParameters(jwtHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(32))
              .build();

      JwtHmacParameters jwtHmacKidParameters =
          JwtHmacParameters.builder()
              .setKeySizeBytes(32)
              .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
              .build();
      JwtHmacKey jwtHmacKidKey =
          JwtHmacKey.builder()
              .setParameters(jwtHmacKidParameters)
              .setKeyBytes(SecretBytes.randomBytes(32))
              .setIdRequirement(123)
              .build();

      JwtEcdsaParameters jwtEcdsaParameters =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JwtEcdsaPublicKey jwtEcdsaPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaKidParameters =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JwtEcdsaPublicKey jwtEcdsaKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaKidParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaKidPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Parameters)
              .setModulus(MODULUS)
              .build();
      RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey =
          RsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1PublicKey.getRsaSsaPkcs1PublicKey())
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
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1PublicKey)
              .setRsaSsaPkcs1PrivateKey(rsaSsaPkcs1PrivateKey)
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssParameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssPublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssParameters)
              .setModulus(MODULUS)
              .build();
      RsaSsaPssPrivateKey rsaSsaPssPrivateKey =
          RsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssPublicKey.getRsaSsaPssPublicKey())
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
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssPrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssPublicKey)
              .setRsaSsaPssPrivateKey(rsaSsaPssPrivateKey)
              .build();

      MlDsaPrivateKey mlDsa44PrivateKey =
          (MlDsaPrivateKey)
              MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                      MlDsaParameters.create(
                          MlDsaParameters.MlDsaInstance.ML_DSA_44,
                          MlDsaParameters.Variant.NO_PREFIX))
                  .getPrivateKey();
      JwtMlDsaParameters jwtMlDsaParameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
      JwtMlDsaPublicKey jwtMlDsaPublicKey =
          JwtMlDsaPublicKey.builder()
              .setParameters(jwtMlDsaParameters)
              .setPublicKeyBytes(mlDsa44PrivateKey.getPublicKey().getSerializedPublicKey())
              .build();
      JwtMlDsaPrivateKey jwtMlDsaPrivateKey =
          JwtMlDsaPrivateKey.create(jwtMlDsaPublicKey, mlDsa44PrivateKey.getPrivateSeed());

      JwtMlDsaParameters jwtMlDsaKidParameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
              JwtMlDsaParameters.Algorithm.ML_DSA_44);
      JwtMlDsaPublicKey jwtMlDsaKidPublicKey =
          JwtMlDsaPublicKey.builder()
              .setParameters(jwtMlDsaKidParameters)
              .setPublicKeyBytes(mlDsa44PrivateKey.getPublicKey().getSerializedPublicKey())
              .setIdRequirement(123)
              .build();
      JwtMlDsaPrivateKey jwtMlDsaKidPrivateKey =
          JwtMlDsaPrivateKey.create(jwtMlDsaKidPublicKey, mlDsa44PrivateKey.getPrivateSeed());

      jwtPrivateKeys =
          new JwtSignaturePrivateKey[] {
            jwtEcdsaPrivateKey,
            jwtEcdsaKidPrivateKey,
            jwtRsaSsaPkcs1PrivateKey,
            jwtRsaSsaPssPrivateKey,
            jwtMlDsaPrivateKey,
            jwtMlDsaKidPrivateKey,
          };
      jwtHmacKeys =
          new JwtHmacKey[] {
            jwtHmacKey, jwtHmacKidKey,
          };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeys")
  public static JwtSignaturePrivateKey[] jwtPrivateKeys;

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtHmacKeys")
  public static JwtHmacKey[] jwtHmacKeys;

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will be skipped.
    }
    createTestKeys();
  }

  @Test
  public void get_isNotNull() throws Exception {
    assertThat(JwtConfig2026.get()).isNotNull();
  }

  @Theory
  public void jwtMac_computeVerify_works(@FromDataPoints("jwtHmacKeys") JwtHmacKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips() || TestUtil.isTsan()) {
      return;
    }

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    JwtMac jwtMac = keysetHandle.getPrimitive(JwtConfig2026.get(), JwtMac.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String compact = jwtMac.computeMacAndEncode(rawToken);
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(compact, validator);

    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Theory
  public void getPrimitive_signVerify_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TinkFipsUtil.useOnlyFips() || TestUtil.isTsan()) {
      return;
    }
    if ((key instanceof JwtMlDsaPrivateKey) && !MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);

    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Theory
  public void serializeAndParsePrivateKey_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = JwtConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParsePublicKey_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
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

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = JwtConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeAndParseJwtHmacKey_works(@FromDataPoints("jwtHmacKeys") JwtHmacKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = JwtConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseJwtHmacParameters_works(
      @FromDataPoints("jwtHmacKeys") JwtHmacKey key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = JwtConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void createKey_works(@FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips() || TestUtil.isTsan()) {
      return;
    }
    if ((key instanceof JwtMlDsaPrivateKey) && !MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), JwtConfig2026.get());

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Theory
  public void createJwtHmacKey_works(@FromDataPoints("jwtHmacKeys") JwtHmacKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips() || TestUtil.isTsan()) {
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), JwtConfig2026.get());

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }
}
