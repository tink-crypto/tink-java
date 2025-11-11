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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for MlDsaSignKeyManager. */
@RunWith(Theories.class)
public class MlDsaSignKeyManagerConscryptTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    try {
      if (!Util.isAndroid() && Conscrypt.isAvailable()) {
        Security.addProvider(Conscrypt.newProvider());
      }
    } catch (Throwable cause) {
      throw new IllegalStateException(
          "Cannot test MlDsaSignKeyManager without Conscrypt provider", cause);
    }
    MlDsaSignKeyManager.registerPair();
  }

  @Test
  public void registerPair_throwsInFips() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, MlDsaSignKeyManager::registerPair);
  }

  @DataPoints("templateNames")
  public static final String[] keyTemplates = new String[] {"ML_DSA_65", "ML_DSA_65_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));

    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Theory
  public void testCreateSignAndVerifyFromTemplate(
      @FromDataPoints("templateNames") String templateName) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    byte[] data = "data".getBytes(UTF_8);

    byte[] signature = signer.sign(data);

    verifier.verify(signature, data);
  }

  @Theory
  public void testCreateSignAndVerifyFromTemplate_wrongMessage_throws(
      @FromDataPoints("templateNames") String templateName) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] wrongData = "wrong data".getBytes(UTF_8);

    byte[] signature = signer.sign(data);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, wrongData));
  }

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);

    MlDsaPrivateKey key0 = (MlDsaPrivateKey) KeysetHandle.generateNew(parameters).getAt(0).getKey();
    MlDsaPrivateKey key1 = (MlDsaPrivateKey) KeysetHandle.generateNew(parameters).getAt(0).getKey();

    assertFalse(key0.equalsKey(key1));
  }

  @Test
  public void testCreateSignAndVerifyFromParameters_works() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    byte[] data = "data".getBytes(UTF_8);

    byte[] signature = signer.sign(data);

    verifier.verify(signature, data);
  }

  @Test
  public void testCreateSignAndVerifyFromParameters_wrongParameters_throws() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX);
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(parameters));
  }

  @Test
  public void testCreateSignAndVerifyFromParameters_wrongMessage_throws() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] wrongData = "wrong data".getBytes(UTF_8);

    byte[] signature = signer.sign(data);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, wrongData));
  }
}
