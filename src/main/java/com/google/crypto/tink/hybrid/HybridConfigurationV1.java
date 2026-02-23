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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import java.security.GeneralSecurityException;

/**
 * HybridConfigurationV1 contains the following algorithms for HybridEncrypt/HybridDecrypt:
 *
 * <ul>
 *   <li>EciesAeadHkdf
 *   <li>Hpke
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class HybridConfigurationV1 {
  private HybridConfigurationV1() {}

  private static final HybridEncryptWrapper HYBRID_ENCRYPT_WRAPPER = new HybridEncryptWrapper();
  private static final HybridDecryptWrapper HYBRID_DECRYPT_WRAPPER = new HybridDecryptWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(HybridEncrypt.class)) {
          return clazz.cast(
              HYBRID_ENCRYPT_WRAPPER.wrap(
                  keysetHandle, HybridConfigurationV1::createHybridEncrypt));
        }
        if (clazz.equals(HybridDecrypt.class)) {
          return clazz.cast(
              HYBRID_DECRYPT_WRAPPER.wrap(
                  keysetHandle, HybridConfigurationV1::createHybridDecrypt));
        }
        throw new GeneralSecurityException(
            "HybridConfigurationV1 can only create HybridEncrypt and HybridDecrypt primitives");
      }
    };
  }

  private static HybridEncrypt createHybridEncrypt(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof EciesPublicKey) {
      return EciesAeadHkdfHybridEncrypt.create((EciesPublicKey) key);
    }
    if (key instanceof HpkePublicKey) {
      return HpkeEncrypt.create((HpkePublicKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  private static HybridDecrypt createHybridDecrypt(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof EciesPrivateKey) {
      return EciesAeadHkdfHybridDecrypt.create((EciesPrivateKey) key);
    }
    if (key instanceof HpkePrivateKey) {
      return HpkeDecrypt.create((HpkePrivateKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  /**
   * Returns an instance of the {@code HybridConfigurationV1}.
   */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant HybridConfigurationV1 in FIPS mode");
    }
    return CONFIGURATION;
  }
}
