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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.runner.RunWith;

// Test the functionality of MlDsaSignKeyManager that should work regardless of the
// Conscrypt's presence.
@RunWith(Theories.class)
public class MlDsaSignKeyManagerTest {
  @Test
  public void registerPair_doesNotThrowWhenNotInFips() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    MlDsaSignKeyManager.registerPair();
  }

  @Test
  public void registerPair_registersParametersProtoSerialization() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    MlDsaSignKeyManager.registerPair();
    MutableSerializationRegistry registry = MutableSerializationRegistry.globalInstance();

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    Parameters parsedParameters =
        registry.parseParameters(
            registry.serializeParameters(parameters, ProtoParametersSerialization.class));

    assertThat(parsedParameters).isEqualTo(parameters);
  }

  @Test
  public void registerPair_registersPublicKeyProtoSerialization() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    MlDsaSignKeyManager.registerPair();
    MutableSerializationRegistry registry = MutableSerializationRegistry.globalInstance();

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(Bytes.copyFrom(new byte[1952])) // Size for ML-DSA-65
            .build();
    Key parsedPublicKey =
        registry.parseKey(
            registry.serializeKey(publicKey, ProtoKeySerialization.class, null), null);

    assertThat(parsedPublicKey.equalsKey(publicKey)).isTrue();
  }

  @Test
  public void registerPair_registersPrivateKeyProtoSerialization() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    MlDsaSignKeyManager.registerPair();
    MutableSerializationRegistry registry = MutableSerializationRegistry.globalInstance();

    MlDsaParameters parameters = MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);
    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(Bytes.copyFrom(new byte[1952])) // Size for ML-DSA-65
            .build();
    MlDsaPrivateKey privateKey =
        MlDsaPrivateKey.createWithoutVerification(
            publicKey, SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()));
    Key parsedPrivateKey =
        registry.parseKey(
            registry.serializeKey(
                privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
            InsecureSecretKeyAccess.get());

    assertThat(parsedPrivateKey.equalsKey(privateKey)).isTrue();
  }

  @Test
  public void getPublicKeyType_works() throws Exception {
    assertThat(MlDsaSignKeyManager.getPublicKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.MlDsaPublicKey");
  }

  @Test
  public void getPrivateKeyType_works() throws Exception {
    assertThat(MlDsaSignKeyManager.getPrivateKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey");
  }

  @Test
  public void registerPair_throwsInFips() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, MlDsaSignKeyManager::registerPair);
  }
}
