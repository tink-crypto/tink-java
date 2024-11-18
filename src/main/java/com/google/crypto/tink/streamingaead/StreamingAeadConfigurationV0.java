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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import java.security.GeneralSecurityException;

/**
 * StreamingAeadConfigurationV0 contains the following algorithms for StreamingAEAD:
 *
 * <ul>
 *   <li>AesGcmHkdfStreaming
 *   <li>AesCtrHmacStreaming
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class StreamingAeadConfigurationV0 {
  private StreamingAeadConfigurationV0() {}

  private static final InternalConfiguration INTERNAL_CONFIGURATION = create();

  private static InternalConfiguration create() {
    try {
      PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

      // Register StreamingAead wrapper and concrete primitives.
      StreamingAeadWrapper.registerToInternalPrimitiveRegistry(builder);
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AesGcmHkdfStreaming::create, AesGcmHkdfStreamingKey.class, StreamingAead.class));
      builder.registerPrimitiveConstructor(
          PrimitiveConstructor.create(
              AesCtrHmacStreaming::create, AesCtrHmacStreamingKey.class, StreamingAead.class));

      return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Returns an instance of the {@code StreamingAeadConfigurationV0}.
   */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant StreamingAead in FIPS mode");
    }
    return INTERNAL_CONFIGURATION;
  }
}
