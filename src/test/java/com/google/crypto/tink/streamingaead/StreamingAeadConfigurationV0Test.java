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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.streamingaead.internal.AesCtrHmacStreamingProtoSerialization;
import com.google.crypto.tink.streamingaead.internal.AesGcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class StreamingAeadConfigurationV0Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, StreamingAeadConfigurationV0::get);
  }

  @Test
  public void config_containsAesGcmHkdfStreamingAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesGcmHkdfStreamingProtoSerialization.register();
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setCiphertextSegmentSizeBytes(100)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(parameters, SecretBytes.randomBytes(32));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(StreamingAeadConfigurationV0.get(), StreamingAead.class))
        .isNotNull();
  }

  @Test
  public void config_containsAesCtrHmacStreamingAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCtrHmacStreamingProtoSerialization.register();
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(48)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(60)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(parameters, SecretBytes.randomBytes(48));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(StreamingAeadConfigurationV0.get(), StreamingAead.class))
        .isNotNull();
  }

  @Test
  public void config_handlesAesGcmHkdfLegacyKeyForStreamingAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.AesGcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(com.google.crypto.tink.proto.HashType.SHA256)
                        .setDerivedKeySize(32)
                        .setCiphertextSegmentSize(61)
                        .build())
                .setKeyValue(random32ByteKeyValue)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    AesGcmHkdfStreamingProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(StreamingAeadConfigurationV0.get(), StreamingAead.class))
        .isNotNull();
  }

  private final ByteString random32ByteKeyValue =
      ByteString.copyFrom(SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get()));

  @Test
  public void config_handlesAesCtrHmacLegacyKeyForStreamingAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
                .setKeyValue(random32ByteKeyValue)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setHkdfHashType(com.google.crypto.tink.proto.HashType.SHA256)
                        .setHmacParams(
                            com.google.crypto.tink.proto.HmacParams.newBuilder()
                                .setTagSize(16)
                                .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                                .build())
                        .setCiphertextSegmentSize(59)
                        .setDerivedKeySize(32)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    AesCtrHmacStreamingProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(StreamingAeadConfigurationV0.get(), StreamingAead.class))
        .isNotNull();
  }
}
