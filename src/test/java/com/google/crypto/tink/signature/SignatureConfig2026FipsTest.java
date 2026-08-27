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

import static com.google.common.truth.Truth.assertWithMessage;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.internal.CompositeMlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SlhDsaTestUtil;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for SignatureConfig2026 which run under fips mode.
 *
 * <p>We test this by tagging the test with "fips" which will run it three configurations: *
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=False,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True and BORINGSSL_FIPS=0 in C++.`
 */
@RunWith(JUnit4.class)
public class SignatureConfig2026FipsTest {
  @BeforeClass
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Nullable
  private static SignaturePrivateKey createEcdsaPrivateKeyOrNull() {
    try {
      return EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey();
    } catch (IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createRsaSsaPkcs1PrivateKey2048BitOrNull() {
    try {
      return RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey();
    } catch (IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createRsaSsaPkcs1PrivateKey4096BitOrNull() {
    try {
      RsaSsaPkcs1Parameters parameters =
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(RsaSsaPkcs1Parameters.F4)
              .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .build();
      return RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(parameters, null);
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createRsaSsaPssPrivateKey2048BitOrNull() {
    try {
      return RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey();
    } catch (IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createRsaSsaPssPrivateKey4096BitOrNull() {
    try {
      RsaSsaPssParameters parameters =
          RsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(RsaSsaPssParameters.F4)
              .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
              .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
              .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
              .setSaltLengthBytes(32)
              .build();
      return RsaSsaPssTestUtil.privateKeyFor4096BitParameters(parameters, null);
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createEd25519PrivateKeyOrNull() {
    try {
      return Ed25519TestUtil.createTestVector0().getPrivateKey();
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createMlDsaPrivateKeyOrNull() {
    try {
      return MlDsaTestUtil.getMlDsaValidSignatureTestVector(
              MlDsaParameters.create(
                  MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
          .getPrivateKey();
    } catch (IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createSlhDsaPrivateKeyOrNull() {
    try {
      return SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors()
          .findFirst()
          .get()
          .getPrivateKey();
    } catch (IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static SignaturePrivateKey createCompositeMlDsaPrivateKeyOrNull() {
    try {
      return CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(
          CompositeMlDsaTestUtil.compositeMlDsaTestVectors.get(2));
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  /**
   * Returns Keys which should work.
   *
   * <p>If `//src/main/java/com/google/crypto/tink/config:use_only_fips=False` then this is all
   * keys. If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and BoringSSL was
   * compiled with `BORINGSSL_FIPS` then these are the FIPS keys in BoringSSL. If
   * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and `BORINGSSL_FIPS=0` then
   * this is the empty list.
   */
  private static ArrayList<SignaturePrivateKey> createKeysWhichShouldWork() {
    ArrayList<SignaturePrivateKey> result = new ArrayList<>();
    if (TinkFipsUtil.fipsModuleAvailable() || !TinkFipsUtil.useOnlyFips()) {
      result.add(createEcdsaPrivateKeyOrNull());
      result.add(createRsaSsaPkcs1PrivateKey2048BitOrNull());
      result.add(createRsaSsaPssPrivateKey2048BitOrNull());
    }

    if (!TinkFipsUtil.useOnlyFips()) {
      result.add(createEd25519PrivateKeyOrNull());
      result.add(createMlDsaPrivateKeyOrNull());
      result.add(createSlhDsaPrivateKeyOrNull());
      result.add(createRsaSsaPkcs1PrivateKey4096BitOrNull());
      result.add(createRsaSsaPssPrivateKey4096BitOrNull());
      if (CompositeMlDsaVerifyConscrypt.isSupported()) {
        result.add(createCompositeMlDsaPrivateKeyOrNull());
      }
    }
    // Of the supported keys, no key should be null.
    for (int i = 0; i < result.size(); i++) {
      assertWithMessage("Position %s is null", i).that(result.get(i)).isNotNull();
    }
    return result;
  }

  /**
   * Returns Keys which should fail.
   *
   * <p>If `//src/main/java/com/google/crypto/tink/config:use_only_fips=False` then this is empty.
   * If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and BoringSSL was
   * compiled with `BORINGSSL_FIPS` then these are the keys which can still be created in Tink, and
   * which are not FIPS. (Note that it is acceptable if creating the key fails in this case, then we
   * simply ignore the key). If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True`
   * and `BORINGSSL_FIPS=0` then this is all keys which can still be created.
   */
  private static ArrayList<SignaturePrivateKey> createKeysWhichShouldFail() {
    ArrayList<SignaturePrivateKey> result = new ArrayList<>();
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      SignaturePrivateKey ecdsaKey = createEcdsaPrivateKeyOrNull();
      if (ecdsaKey != null) {
        result.add(ecdsaKey);
      }
      SignaturePrivateKey rsaPkcs1Key = createRsaSsaPkcs1PrivateKey2048BitOrNull();
      if (rsaPkcs1Key != null) {
        result.add(rsaPkcs1Key);
      }
      SignaturePrivateKey rsaPssKey = createRsaSsaPssPrivateKey2048BitOrNull();
      if (rsaPssKey != null) {
        result.add(rsaPssKey);
      }
    }

    if (TinkFipsUtil.useOnlyFips()) {
      SignaturePrivateKey ed25519Key = createEd25519PrivateKeyOrNull();
      if (ed25519Key != null) {
        result.add(ed25519Key);
      }
      SignaturePrivateKey mlDsaKey = createMlDsaPrivateKeyOrNull();
      if (mlDsaKey != null) {
        result.add(mlDsaKey);
      }
      SignaturePrivateKey slhDsaKey = createSlhDsaPrivateKeyOrNull();
      if (slhDsaKey != null) {
        result.add(slhDsaKey);
      }
      SignaturePrivateKey compositeMlDsaKey = createCompositeMlDsaPrivateKeyOrNull();
      if (compositeMlDsaKey != null) {
        result.add(compositeMlDsaKey);
      }
      SignaturePrivateKey rsaPkcs1Key4096 = createRsaSsaPkcs1PrivateKey4096BitOrNull();
      if (rsaPkcs1Key4096 != null) {
        result.add(rsaPkcs1Key4096);
      }
      SignaturePrivateKey rsaPssKey4096 = createRsaSsaPssPrivateKey4096BitOrNull();
      if (rsaPssKey4096 != null) {
        result.add(rsaPssKey4096);
      }
    }
    return result;
  }

  @Test
  public void getPrimitive_signVerify_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
      KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

      PublicKeySign signer = handle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class);
      PublicKeyVerify verifier =
          publicKeyHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

      byte[] message = "message".getBytes(UTF_8);
      byte[] signature = signer.sign(message);
      verifier.verify(signature, message);
    }
  }

  @Test
  public void serializeAndParsePrivateKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = SignatureConfig2026.get();
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
    for (SignaturePrivateKey key : createKeysWhichShouldWork()) {
      SignaturePublicKey publicKey = key.getPublicKey();
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(publicKey).makePrimary();
      if (publicKey.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(publicKey.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = SignatureConfig2026.get();
      byte[] serialized = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, config);
      KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed.equalsKeyset(keysetHandle)).isTrue();
    }
  }

  @Test
  public void serializeAndParseParameters_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldWork()) {
      Parameters parameters = key.getParameters();
      Configuration config = SignatureConfig2026.get();
      byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
      Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed).isEqualTo(parameters);
    }
  }

  @Test
  public void createKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldWork()) {
      Configuration config = SignatureConfig2026.get();

      KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

      assertWithMessage("Failed for key: %s", key)
          .that(handle.getPrimary().getKey().getParameters())
          .isEqualTo(key.getParameters());
    }
  }

  @Test
  public void getPrimitive_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldFail()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
      KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

      Configuration configuration = SignatureConfig2026.get();
      assertThrows(
          "Expected getPrimitive(PublicKeySign) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, PublicKeySign.class));
      assertThrows(
          "Expected getPrimitive(PublicKeyVerify) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> publicKeyHandle.getPrimitive(configuration, PublicKeyVerify.class));
    }
  }

  @Test
  public void createKey_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (SignaturePrivateKey key : createKeysWhichShouldFail()) {
      Configuration config = SignatureConfig2026.get();

      assertThrows(
          "Expected generateNew to throw for key: " + key,
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
    }
  }

  // Note: we do not check parse/serialize for Non-FIPS keys -- we are fine with either behavior.
}
