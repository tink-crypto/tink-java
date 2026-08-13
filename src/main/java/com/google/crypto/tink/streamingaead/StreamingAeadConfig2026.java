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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.streamingaead.internal.WrappedStreamingAead;
import com.google.crypto.tink.streamingaead.subtle.AesCtrHmacStreamingAead;
import com.google.crypto.tink.streamingaead.subtle.AesCtrHmacStreamingProtoSerialization;
import com.google.crypto.tink.streamingaead.subtle.AesGcmHkdfStreamingAead;
import com.google.crypto.tink.streamingaead.subtle.AesGcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * StreamingAeadConfig2026 contains the following primitives and algorithms for {@link
 * StreamingAead}:
 *
 * <ul>
 *   <li>AesCtrHmacStreaming
 *   <li>AesGcmHkdfStreaming
 * </ul>
 */
public final class StreamingAeadConfig2026 {
  private StreamingAeadConfig2026() {}

  private static final Configuration CONFIGURATION = create();
  private static final Configuration EMPTY_CONFIGURATION =
      new ProtoBasedConfigurationBuilder().build();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() {
    if (TinkFipsUtil.useOnlyFips()) {
      return EMPTY_CONFIGURATION;
    }
    return CONFIGURATION;
  }

  private static final String AES_CTR_HMAC_STREAMING_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
  private static final String AES_GCM_HKDF_STREAMING_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(StreamingAead.class, StreamingAead.class, WrappedStreamingAead::wrap)
        // AesCtrHmacStreaming
        .addKeyCreator(
            AesCtrHmacStreamingParameters.class,
            StreamingAeadConfig2026::createAesCtrHmacStreamingKey)
        .addPrimitiveConstructor(
            AesCtrHmacStreamingAead::create, AesCtrHmacStreamingKey.class, StreamingAead.class)
        .addKeySerializer(
            AesCtrHmacStreamingKey.class, AesCtrHmacStreamingProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesCtrHmacStreamingParameters.class,
            AesCtrHmacStreamingProtoSerialization::serializeParameters)
        .addKeyParser(
            AES_CTR_HMAC_STREAMING_TYPE_URL, AesCtrHmacStreamingProtoSerialization::parseKey)
        .addParametersParser(
            AES_CTR_HMAC_STREAMING_TYPE_URL, AesCtrHmacStreamingProtoSerialization::parseParameters)
        // AesGcmHkdfStreaming
        .addKeyCreator(
            AesGcmHkdfStreamingParameters.class,
            StreamingAeadConfig2026::createAesGcmHkdfStreamingKey)
        .addPrimitiveConstructor(
            AesGcmHkdfStreamingAead::create, AesGcmHkdfStreamingKey.class, StreamingAead.class)
        .addKeySerializer(
            AesGcmHkdfStreamingKey.class, AesGcmHkdfStreamingProtoSerialization::serializeKey)
        .addParametersSerializer(
            AesGcmHkdfStreamingParameters.class,
            AesGcmHkdfStreamingProtoSerialization::serializeParameters)
        .addKeyParser(
            AES_GCM_HKDF_STREAMING_TYPE_URL, AesGcmHkdfStreamingProtoSerialization::parseKey)
        .addParametersParser(
            AES_GCM_HKDF_STREAMING_TYPE_URL, AesGcmHkdfStreamingProtoSerialization::parseParameters)
        .build();
  }

  @AccessesPartialKey
  private static AesCtrHmacStreamingKey createAesCtrHmacStreamingKey(
      AesCtrHmacStreamingParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("idRequirement must be null");
    }
    return AesCtrHmacStreamingKey.create(
        parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }

  @AccessesPartialKey
  private static AesGcmHkdfStreamingKey createAesGcmHkdfStreamingKey(
      AesGcmHkdfStreamingParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("idRequirement must be null");
    }
    return AesGcmHkdfStreamingKey.create(
        parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }
}
