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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import java.security.GeneralSecurityException;

/**
 * PrfConfigurationV0 contains the following algorithms for PrfSet:
 *
 * <ul>
 *   <li>HmacPrf
 *   <li>HkdfPrf
 *   <li>AesCmacPrf
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class PrfConfigurationV0 {
  private PrfConfigurationV0() {}

  private static final PrfSetWrapper PRF_SET_WRAPPER = new PrfSetWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(PrfSet.class)) {
          return clazz.cast(PRF_SET_WRAPPER.wrap(keysetHandle, PrfConfigurationV0::createPrf));
        }
        throw new GeneralSecurityException("PrfConfigurationV0 can only create PrfSet primitive");
      }
    };
  }

  /** Returns an instance of the {@code PrfConfigurationV0}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant PrfConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static Prf createPrf(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof LegacyProtoKey) {
      Key reparsedKey =
          MutableSerializationRegistry.globalInstance()
              .parseKey(
                  ((LegacyProtoKey) key).getSerialization(InsecureSecretKeyAccess.get()),
                  InsecureSecretKeyAccess.get());
      key = reparsedKey;
    }

    if (key instanceof HmacPrfKey) {
      return PrfHmacJce.create((HmacPrfKey) key);
    }
    if (key instanceof HkdfPrfKey) {
      return createHkdfPrf((HkdfPrfKey) key);
    }
    if (key instanceof AesCmacPrfKey) {
      return createAesCmacPrf((AesCmacPrfKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  // We use a somewhat larger minimum key size than usual, because PRFs might be used by many users,
  // in which case the security can degrade by a factor depending on the number of users. (Discussed
  // for example in https://eprint.iacr.org/2012/159)
  private static final int MIN_HKDF_PRF_KEY_SIZE = 32;

  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() < MIN_HKDF_PRF_KEY_SIZE) {
      throw new GeneralSecurityException(
          "HkdfPrf key size must be at least " + MIN_HKDF_PRF_KEY_SIZE);
    }
    if (key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA256
        && key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("HkdfPrf hash type must be SHA256 or SHA512");
    }
    return PrfImpl.wrap(HkdfStreamingPrf.create(key));
  }

  private static Prf createAesCmacPrf(AesCmacPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != 32) {
      throw new GeneralSecurityException("AesCmacPrf key size must be 32 bytes");
    }
    return PrfAesCmac.create(key);
  }
}
