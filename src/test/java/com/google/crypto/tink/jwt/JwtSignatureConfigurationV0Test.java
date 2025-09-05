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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
import com.google.crypto.tink.signature.PublicKeySignWrapper;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class JwtSignatureConfigurationV0Test {

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

  private static final String CUSTOM_KID_VALUE =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

  private static void createTestKeys() {
    try {
      JwtEcdsaParameters jwtEcdsaEs256RawParameters =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256RawParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256RawPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs256Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256Parameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256PublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs256CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256CustomKidParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs256WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256CustomKidParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512RawParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512RawParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512RawPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512Parameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512PublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512CustomKidParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs512WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512CustomKidParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384RawParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384RawParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384RawPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384Parameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384PublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384CustomKidParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs384WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384CustomKidParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      jwtPrivateKeys =
          new JwtSignaturePrivateKey[] {
            jwtEcdsaEs256RawPrivateKey,
            jwtEcdsaEs256PrivateKey,
            jwtEcdsaEs384RawPrivateKey,
            jwtEcdsaEs384PrivateKey,
            jwtEcdsaEs512RawPrivateKey,
            jwtEcdsaEs512PrivateKey,
          };

      jwtPrivateKeyPairs =
          new JwtSignaturePrivateKey[][] {
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs256RawPrivateKey, jwtEcdsaEs256CustomKidPrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs384RawPrivateKey, jwtEcdsaEs384CustomKidPrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs512RawPrivateKey, jwtEcdsaEs512CustomKidPrivateKey,
            },
          };

      jwtPrivateKeyPairsDifferentKids =
          new JwtSignaturePrivateKey[][] {
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs256CustomKidPrivateKey, jwtEcdsaEs256WrongKidPrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs384CustomKidPrivateKey, jwtEcdsaEs384WrongKidPrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs512CustomKidPrivateKey, jwtEcdsaEs512WrongKidPrivateKey
            },
          };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeys")
  public static JwtSignaturePrivateKey[] jwtPrivateKeys;

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeyPairs")
  public static JwtSignaturePrivateKey[][] jwtPrivateKeyPairs;

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeyPairsDifferentKids")
  public static JwtSignaturePrivateKey[][] jwtPrivateKeyPairsDifferentKids;

  @BeforeClass
  public static void setUp() throws Exception {
    createTestKeys();

    JwtEcdsaProtoSerialization.register();
    EcdsaProtoSerialization.register();
    XChaCha20Poly1305ProtoSerialization.register();

    // Needed until we replaced RegistryConfiguration with SignatureConfiguration.
    PublicKeySignWrapper.register();
    EcdsaSignKeyManager.registerPair(false);
  }

  @Test
  public void get_works() throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    assertThat(JwtSignatureConfigurationV0.get()).isNotNull();
  }

  @Test
  public void getInFipsModeWithoutBoringCrypto_fails() throws Exception {
    assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(GeneralSecurityException.class, JwtSignatureConfigurationV0::get);
  }

  // The following test functions are inspired by
  // src/test/java/com/google/crypto/tink/jwt/JwtEcdsaSignKeyManagerTest.java.

  // This also tests that all the expected key types -- Ecdsa, RsaSsaPkcs1, and RsaSsaPss --
  // are indeed supported by the Configuration.
  @Theory
  public void getPrimitive_signVerify_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .allowMissingExpiration()
                .expectTypeHeader("typeHeader")
                .build());

    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  @Theory
  public void getPrimitive_signVerifyDifferentKey_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherKeysetHandle;
    if (key.equalsKey(jwtPrivateKeys[0]) || key.equalsKey(jwtPrivateKeys[1])) {
      otherKeysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(jwtPrivateKeys[2]).withFixedId(123).makePrimary())
              .build();
    } else {
      otherKeysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(jwtPrivateKeys[0]).withFixedId(123).makePrimary())
              .build();
    }
    JwtPublicKeyVerify otherVerifier =
        otherKeysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Theory
  public void getPrimitive_signVerifyHeaderModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("issuer").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Theory
  public void getPrimitive_signVerifyPayloadModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Theory
  public void getPrimitive_signVerifyRawBitFlipped_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    // Skip the test under TSAN, it is too slow.
    if (TestUtil.isTsan()) {
      return;
    }
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    // We ignore the last byte because the bas64 decoder ignores some of the bits.
    for (int i = 0; i < signedCompact.length() - 1; i++) {
      for (int b = 0; b < 8; b++) {
        StringBuilder stringBuilder = new StringBuilder(signedCompact);
        stringBuilder.setCharAt(i, (char) (signedCompact.charAt(i) ^ (1 << b)));
        String alteredCompact = stringBuilder.toString();

        assertThrows(
            GeneralSecurityException.class,
            () -> verifier.verifyAndDecode(alteredCompact, validator));
      }
    }
  }

  @Theory
  public void getPrimitive_signVerifyBitFlipped_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    // Skip the test under TSAN, it is too slow.
    if (TestUtil.isTsan()) {
      return;
    }
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    for (int i = 0; i < signedCompactWithType.length() - 1; i++) {
      for (int b = 0; b < 8; b++) {
        StringBuilder stringBuilder = new StringBuilder(signedCompactWithType);
        stringBuilder.setCharAt(i, (char) (signedCompactWithType.charAt(i) ^ (1 << b)));
        String alteredCompactWithType = stringBuilder.toString();

        assertThrows(
            GeneralSecurityException.class,
            () ->
                verifier.verifyAndDecode(
                    alteredCompactWithType,
                    JwtValidator.newBuilder()
                        .allowMissingExpiration()
                        .expectTypeHeader("typeHeader")
                        .build()));
      }
    }
  }

  private static String generateSignedCompact(
      PublicKeySign rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature = Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  private static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.CurveType.NIST_P256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.CurveType.NIST_P384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static EcdsaParameters.HashType getHash(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @Theory
  public void getPrimitive_signVerifyEcdsaRawDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                == JwtEcdsaParameters.KidStrategy.IGNORED);
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPrivateKey).withFixedId(123).makePrimary())
            .build();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JsonObject payload = new JsonObject();
    payload.addProperty("jid", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Normal, valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String normalSignedCompact = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // for raw keys, the validation should work even if a "kid" header is present.
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Theory
  public void getPrimitive_signVerifyEcdsaTinkDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                != JwtEcdsaParameters.KidStrategy.IGNORED);
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPrivateKey).withFixedId(123).makePrimary())
            .build();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    String kid = jwtEcdsaPrivateKey.getPublicKey().getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Normal, valid signed token.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    normalHeader.addProperty("kid", kid);
    String normalToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in the header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("kid", kid);
    headerWithBadAlg.addProperty(
        "alg",
        // "RS{256,384,512}"
        new StringBuilder(jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName())
            .replace(0, 1, "R")
            .toString());
    String badAlgToken = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(badAlgToken, validator));
  }

  @SuppressWarnings("AvoidObjectArrays")
  @Theory
  public void getPrimitive_signVerifyWithCustomKid_works(
      @FromDataPoints("jwtPrivateKeyPairs") JwtSignaturePrivateKey[] keys) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[0]).withRandomId().makePrimary())
            .build();
    KeysetHandle keysetHandleWithCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[1]).withFixedId(123).makePrimary())
            .build();

    JwtPublicKeySign signerWithKid =
        keysetHandleWithCustomKid.getPrimitive(
            JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeySign signerWithoutKid =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo(CUSTOM_KID_VALUE);
    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify verifierWithKid =
        keysetHandleWithCustomKid
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Even if custom_kid is set, we don't require a "kid" in the header.
    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");

    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
  }

  @SuppressWarnings("AvoidObjectArrays")
  @Theory
  public void getPrimitive_signVerifyWithWrongCustomKid_throws(
      @FromDataPoints("jwtPrivateKeyPairsDifferentKids") JwtSignaturePrivateKey[] keys)
      throws Exception {
    KeysetHandle keysetHandleWithCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[0]).withFixedId(123).makePrimary())
            .build();
    KeysetHandle keysetHandleWithWrongCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[1]).withFixedId(123).makePrimary())
            .build();

    JwtPublicKeySign signerWithKid =
        keysetHandleWithCustomKid.getPrimitive(
            JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        keysetHandleWithWrongCustomKid
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void wrongPrimitive_throws() throws Exception {
    XChaCha20Poly1305Key wrongTypeKey = XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(wrongTypeKey).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), Aead.class));
  }
}
