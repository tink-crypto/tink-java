// Copyright 2024 Google LLC
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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.internal.AesCmacProtoSerialization;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacConfigurationV0Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, MacConfigurationV0::get);
  }

  @Test
  public void config_containsHmacForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HmacProtoSerialization.register();
    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_containsHmacForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HmacProtoSerialization.register();
    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }

  @Test
  public void config_containsAesCmacForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class));
  }

  @Test
  public void config_containsAesCmacForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class));
  }
}
