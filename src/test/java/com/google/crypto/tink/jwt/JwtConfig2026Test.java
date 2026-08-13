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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
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

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_44_sign_seed_test.json
  private static final String PRIVATE_KEY_MLDSA44_SEED_HEX =
      "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
  private static final String PUBLIC_KEY_MLDSA44_HEX =
      "db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac90b1111170a561290ae86b139"
          + "68f2506023c014ba09fa449a26e4e9d35595e73986506cc8790e4d07a94d6c736f7ae78cc5e3e3cf"
          + "025ce06a09252bef97fe92e94cbd107b1844d1a7c690d88bff9e9336f8f58e0bd5ee384de9c7ffbb"
          + "149a6fcd87c77288601d8843e28e0c7a60149d02ebc57b183c39888d98b61cd8ad48135ddb8a1666"
          + "743bb689f44c1a92d52017b6a8fa493eeb839dffb086a9a6c399b194a52f0e4164c96ff8a2a54337"
          + "de24350a866b5fe4195257778e72511221778f1eae5fa93ed3532f696b9b0767aded85f62ea31102"
          + "7c7f5fc4182dcd2864b1c26bd6dcf72ebdedf70471327be0ea1c2ae53e46489c6dbefa512a78fdd7"
          + "be0ad3ada16a7f7b1ece49817b44868a2cc234bfdba556c32cc92ec2c5e8a5d206f2e4ee372d4168"
          + "1e67d1b7e7b0061870c57f600fafca85f98aed8ce4ba76bba961f9ed56e563220d3ced853b6b28e7"
          + "527da0e0912bc932a23c8bab811429bbb4d49b2770bcda44abb932b11c0a5866409fce39fed2b459"
          + "c86c8f6e1ab0aefc5879503f4b21a49b4b2de6760c9b6aaf041144a656a26af39f4578e1d482ddc1"
          + "360ef751d9784b860ec373d415360fe99f32e126a2ac1243430e8bed1bc90b19b3d219c2712edcf8"
          + "1c44b4331f6421088e662b695e1fd8fa5091f616ab60af70f159b63368f1ac60d77b279ed47ef7f2"
          + "4ec2044bb6c2bc76d933ecd568f7e663392afc1d335abac6c03670adf87747dde90052f5cd45f7d3"
          + "0f43a4dc3c500ceb658fce235c171240baca1b5a14733d774b9416c540f53eb83481afc98344b12a"
          + "4309e6222b08d978430467497010314c6f6b8caf65361c216106395275a67d7500dbc120f7918c6f"
          + "8db7aa63fa965b4a22c70dc88f727d768ce2bfc7597fd470184e1c59a6b2e1204cc8c3d052c594d5"
          + "771e0ccc8cfb191f47038b1c0672f07caf4747562d3d76a9816fb1def1391cf0f05fcdbf2a0eb6c2"
          + "1ac24b26e74ee403133e80a79313ddb02c1fa386c6dd1d420195343e3a104aff6d60887f7304fa9e"
          + "3bb59bb55f820dd85b1445c54e9a38dc1c7f3b88eb36a9f48d13455e51c934825ff3cd8bedb2b542"
          + "2344120399eef83a360b83440ebdd8ea6e01c95159e3735bb4408500caa785ca4049891c7331c4ea"
          + "31ad9060ece768fd339e6904f88e27bad3b28845687be2cc9314f300fda56fe3ff2508e54c59123b"
          + "068f86fe00213d5af8da1b1735423ed688f097c306dbc121b81f532fcaf872d9f80596642295d6e4"
          + "bead478644081618ab903b39e9b5e7cc0b5f2742d8337b18d4ad4788db7443e946cafc1762a5da84"
          + "070e8c2fd86d6c633f0b44ee234ba11b9e1440c94a08d0437015279690405353059020fd2f58f15d"
          + "ab18754177244adfb81ceab79c7840bf3884a3d364afc8c453a425fd8c5378eaa7445f8c6256bfbd"
          + "03a66c53e8cf27e2c52f14ef3294afe79cda408f5dff933ca0211a78a4e3be3d9a932558ed71ed19"
          + "bbb57f87937fa3d4a78128491ff096a261045bdd186325c42caa8c7564195a4d2499a1c17d21a52d"
          + "1aacd221d9c8a1866963a20390f2fd43dcf56b308a1c01c38091fd3e04c12b695de497d48bcc268d"
          + "50cb0bed793b8e6937e8d533afd568521f1c9377a3804d38e785674d7ce868d289938e33dda6edc7"
          + "6d25b15fcb38852b7803cfe62f08d9fbd070957c4e6f134973964c9dc009985c8501e7d8f72e7ec2"
          + "85d5289fdd07f64d62acaa9737b039efa7a9d1d175577c6bcf9dddcf692877af38e75263bebe2453"
          + "155be61f0723c274388a532abe29dd7023e327085f4c9dda41839b7b3357ab9d";

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

      JwtMlDsaParameters jwtMlDsaParameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
      JwtMlDsaPublicKey jwtMlDsaPublicKey =
          JwtMlDsaPublicKey.builder()
              .setParameters(jwtMlDsaParameters)
              .setPublicKeyBytes(Bytes.copyFrom(Hex.decode(PUBLIC_KEY_MLDSA44_HEX)))
              .build();
      JwtMlDsaPrivateKey jwtMlDsaPrivateKey =
          JwtMlDsaPrivateKey.create(
              jwtMlDsaPublicKey,
              SecretBytes.copyFrom(
                  Hex.decode(PRIVATE_KEY_MLDSA44_SEED_HEX), InsecureSecretKeyAccess.get()));

      JwtMlDsaParameters jwtMlDsaKidParameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
              JwtMlDsaParameters.Algorithm.ML_DSA_44);
      JwtMlDsaPublicKey jwtMlDsaKidPublicKey =
          JwtMlDsaPublicKey.builder()
              .setParameters(jwtMlDsaKidParameters)
              .setPublicKeyBytes(Bytes.copyFrom(Hex.decode(PUBLIC_KEY_MLDSA44_HEX)))
              .setIdRequirement(123)
              .build();
      JwtMlDsaPrivateKey jwtMlDsaKidPrivateKey =
          JwtMlDsaPrivateKey.create(
              jwtMlDsaKidPublicKey,
              SecretBytes.copyFrom(
                  Hex.decode(PRIVATE_KEY_MLDSA44_SEED_HEX), InsecureSecretKeyAccess.get()));

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
