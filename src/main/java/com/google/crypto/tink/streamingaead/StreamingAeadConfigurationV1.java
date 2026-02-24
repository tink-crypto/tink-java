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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import java.security.GeneralSecurityException;

/**
 * StreamingAeadConfigurationV1 contains the following algorithms for StreamingAEAD:
 *
 * <ul>
 *   <li>AesGcmHkdfStreaming
 *   <li>AesCtrHmacStreaming
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class StreamingAeadConfigurationV1 {
  private StreamingAeadConfigurationV1() {}

  private static final StreamingAeadWrapper STREAMING_AEAD_WRAPPER = new StreamingAeadWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == StreamingAead.class) {
          return clazz.cast(
              STREAMING_AEAD_WRAPPER.wrap(
                  keysetHandle, StreamingAeadConfigurationV1::createStreamingAead));
        }
        throw new GeneralSecurityException(
            "StreamingAeadConfigurationV1 can only create StreamingAead");
      }
    };
  }

  /**
   * Returns an instance of the {@code StreamingAeadConfigurationV1}.
   */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant StreamingAead in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static StreamingAead createStreamingAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesGcmHkdfStreamingKey) {
      return AesGcmHkdfStreaming.create((AesGcmHkdfStreamingKey) key);
    }
    if (key instanceof AesCtrHmacStreamingKey) {
      return AesCtrHmacStreaming.create((AesCtrHmacStreamingKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }
}
