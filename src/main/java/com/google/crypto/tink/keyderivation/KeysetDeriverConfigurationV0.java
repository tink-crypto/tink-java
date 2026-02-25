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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.keyderivation.internal.KeyDeriver;
import com.google.crypto.tink.keyderivation.internal.KeysetDeriverWrapper;
import com.google.crypto.tink.keyderivation.internal.PrfBasedKeyDeriver;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import java.security.GeneralSecurityException;

/**
 * KeysetDeriverConfigurationV0 contains the following algorithms for KeysetDeriver:
 *
 * <ul>
 *   <li>HKDF-PRF-based key derivation
 * </ul>
 *
 * TODO(b/463439649): replace the usage of the global MutableKeyDerivationRegistry by a localised
 * solution.
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class KeysetDeriverConfigurationV0 {
  private KeysetDeriverConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();
  private static final PrimitiveRegistry PRF_REGISTRY = createPrfRegistry();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz == KeysetDeriver.class) {
          return clazz.cast(
              KeysetDeriverWrapper.WRAPPER.wrap(
                  keysetHandle, KeysetDeriverConfigurationV0::createKeyDeriver));
        }
        throw new GeneralSecurityException(
            "KeysetDeriverConfigurationV0 can only create KeysetDeriver primitives");
      }
    };
  }

  private static PrimitiveRegistry createPrfRegistry() {
    try {
      return PrimitiveRegistry.builder()
          .registerPrimitiveConstructor(
              PrimitiveConstructor.create(
                  HkdfStreamingPrf::create, HkdfPrfKey.class, StreamingPrf.class))
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant KeysetDeriverConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static KeyDeriver createHkdfPrfBasedKeyDeriver(PrfBasedKeyDerivationKey key)
      throws GeneralSecurityException {
    // TODO(b/463439649): create the object that would make use of a local
    //   KeyDerivationRegistry.
    KeyDeriver deriver = PrfBasedKeyDeriver.createWithPrfPrimitiveRegistry(PRF_REGISTRY, key);
    Object unused = deriver.deriveKey(new byte[] {1});
    return deriver;
  }

  private static KeyDeriver createKeyDeriver(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof LegacyProtoKey) {
      Key reparsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  ((LegacyProtoKey) key).getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      key = reparsedKey;
    }
    if (key instanceof PrfBasedKeyDerivationKey) {
      return createHkdfPrfBasedKeyDeriver((PrfBasedKeyDerivationKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }
}
