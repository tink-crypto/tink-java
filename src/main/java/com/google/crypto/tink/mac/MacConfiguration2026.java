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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.mac.internal.AesCmacProtoSerialization;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * MacConfiguration2026 contains the following primitives and algorithms for MAC and ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 */
public class MacConfiguration2026 {
  private MacConfiguration2026() {}

  private static final MacWrapper MAC_WRAPPER = new MacWrapper();
  private static final ChunkedMacWrapper CHUNKED_MAC_WRAPPER = new ChunkedMacWrapper();
  private static final Configuration CONFIGURATION = create();
  private static final ProtoKeySerializer SERIALIZER = createProtoKeySerializer();

  /** Returns the {@link Configuration} instance. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant MacConfiguration2026 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == Mac.class) {
          return clazz.cast(MAC_WRAPPER.wrap(keysetHandle, MacConfiguration2026::createMac));
        }
        if (clazz == ChunkedMac.class) {
          return clazz.cast(
              CHUNKED_MAC_WRAPPER.wrap(keysetHandle, MacConfiguration2026::createChunkedMac));
        }
        throw new GeneralSecurityException(
            "MacConfiguration2026 can only create MAC and ChunkedMAC");
      }

      @Override
      @AccessesPartialKey
      public Key createKey(Parameters parameters, @Nullable Integer idRequirement)
          throws GeneralSecurityException {
        if (parameters instanceof AesCmacParameters) {
          AesCmacParameters aesCmacParameters = (AesCmacParameters) parameters;
          return AesCmacKey.builder()
              .setParameters(aesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(aesCmacParameters.getKeySizeBytes()))
              .setIdRequirement(idRequirement)
              .build();
        }
        if (parameters instanceof HmacParameters) {
          HmacParameters hmacParameters = (HmacParameters) parameters;
          return HmacKey.builder()
              .setParameters(hmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(hmacParameters.getKeySizeBytes()))
              .setIdRequirement(idRequirement)
              .build();
        }
        throw new GeneralSecurityException(
            "Unrecognized parameters for MacConfiguration2026:" + parameters);
      }

      @Override
      public <P> P getOrNull(Class<P> clazz) {
        if (clazz.equals(ProtoKeySerializer.class)) {
          return clazz.cast(SERIALIZER);
        }
        return null;
      }
    };
  }

  private static Mac createMac(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesCmacKey) {
      return createAesCmac((AesCmacKey) key);
    }
    if (key instanceof HmacKey) {
      return PrfMac.create((HmacKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  private static ChunkedMac createChunkedMac(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesCmacKey) {
      return createChunkedAesCmac((AesCmacKey) key);
    }
    if (key instanceof HmacKey) {
      return new ChunkedHmacImpl((HmacKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  // We only allow 32-byte AesCmac keys.
  private static final int AES_CMAC_KEY_SIZE_BYTES = 32;

  private static ChunkedMac createChunkedAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return ChunkedAesCmacImpl.create(key);
  }

  private static Mac createAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return PrfMac.create(key);
  }

  private static ProtoKeySerializer createProtoKeySerializer() {
    try {
      SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
      HmacProtoSerialization.register(builder);
      AesCmacProtoSerialization.register(builder);
      return builder.build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
