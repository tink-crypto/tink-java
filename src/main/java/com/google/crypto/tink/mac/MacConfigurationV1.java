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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.subtle.PrfMac;
import java.security.GeneralSecurityException;

/**
 * MacConfigurationV1 contains the following primitives and algorithms for MAC and ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class MacConfigurationV1 {
  private MacConfigurationV1() {}

  private static final MacWrapper MAC_WRAPPER = new MacWrapper();
  private static final ChunkedMacWrapper CHUNKED_MAC_WRAPPER = new ChunkedMacWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == Mac.class) {
          return clazz.cast(MAC_WRAPPER.wrap(keysetHandle, MacConfigurationV1::createMac));
        }
        if (clazz == ChunkedMac.class) {
          return clazz.cast(
              CHUNKED_MAC_WRAPPER.wrap(keysetHandle, MacConfigurationV1::createChunkedMac));
        }
        throw new GeneralSecurityException("MacConfigurationV1 can only create MAC and ChunkedMAC");
      }
    };
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant MacConfigurationV1 in FIPS mode");
    }
    return CONFIGURATION;
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
}
