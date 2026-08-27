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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.internal.CompositeMlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SlhDsaTestUtil;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link SignatureConfig2026}. */
@RunWith(Theories.class)
public class SignatureConfig2026Test {

  private static SignaturePrivateKey[] createKeys() {
    return new SignaturePrivateKey[] {
      EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey(),
      RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey(),
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey(),
      Ed25519TestUtil.createEd25519TestVectors()[0].getPrivateKey(),
      MlDsaTestUtil.getMlDsaValidSignatureTestVector(
              MlDsaParameters.create(
                  MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
          .getPrivateKey(),
      SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors().findFirst().get().getPrivateKey(),
      createCompositeMlDsaKey(),
    };
  }

  private static SignaturePrivateKey createCompositeMlDsaKey() {
    try {
      // #2 is the first test vector with Ed25519 classical component.
      return CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(
          CompositeMlDsaTestUtil.compositeMlDsaTestVectors.get(2));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(
          "Failed to create CompositeMlDsaPrivateKey from test vector", e);
    }
  }

  /**
   * A list of Keys which behave common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   * </ul>
   */
  @DataPoints("keys")
  public static final SignaturePrivateKey[] keys = createKeys();

  private static boolean shouldBeSupported(SignaturePrivateKey key) {
    if (key instanceof CompositeMlDsaPrivateKey) {
      return CompositeMlDsaVerifyConscrypt.isSupported();
    }
    Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel >= 37) {
      // On Android API 37 and above, all signature algorithms should be supported.
      return true;
    }
    if ((key instanceof MlDsaPrivateKey) || (key instanceof SlhDsaPrivateKey)) {
      // ML-DSA and SLH-DSA are not supported on Java without Conscrypt, and on older Android
      // versions.
      return false;
    }
    return true;
  }


  @Theory
  public void getPrimitive_signVerify_works(@FromDataPoints("keys") SignaturePrivateKey key)
      throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

    if (!shouldBeSupported(key)) {
      Configuration configuration = SignatureConfig2026.get();
      assertThrows(
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> publicKeyHandle.getPrimitive(configuration, PublicKeyVerify.class));
      return;
    }

    PublicKeySign signer = handle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        publicKeyHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    byte[] message = "message".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }

  @Theory
  public void serializeAndParsePrivateKey_works(@FromDataPoints("keys") SignaturePrivateKey key)
      throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = SignatureConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParsePublicKey_works(@FromDataPoints("keys") SignaturePrivateKey key)
      throws Exception {
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

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(@FromDataPoints("keys") SignaturePrivateKey key)
      throws Exception {
    Parameters parameters = key.getParameters();
    Configuration config = SignatureConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void createKey_works(@FromDataPoints("keys") SignaturePrivateKey key) throws Exception {
    Configuration config = SignatureConfig2026.get();
    if (!shouldBeSupported(key)) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
      return;
    }

    KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Test
  public void getOrNull_unsupportedClass_returnsNull() throws Exception {
    assertThat(SignatureConfig2026.get().getOrNull(String.class)).isNull();
  }
}
