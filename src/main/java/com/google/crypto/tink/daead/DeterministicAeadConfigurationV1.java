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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.AesSiv;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/**
 * DeterministicAeadConfigurationV1 contains the following algorithms for DeterministicAEAD:
 *
 * <ul>
 *   <li>AesSiv
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class DeterministicAeadConfigurationV1 {
  private DeterministicAeadConfigurationV1() {}

  private static final DeterministicAeadWrapper DETERMINISTIC_AEAD_WRAPPER =
      new DeterministicAeadWrapper();
  private static final Configuration CONFIGURATION = create();

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(DeterministicAead.class)) {
          return clazz.cast(
              DETERMINISTIC_AEAD_WRAPPER.wrap(
                  keysetHandle, DeterministicAeadConfigurationV1::createDeterministicAead));
        }
        throw new GeneralSecurityException(
            "DeterministicAeadConfigurationV1 can only create DeterministicAead primitive");
      }
    };
  }

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant DeterministicAeadConfigurationV1 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static DeterministicAead createDeterministicAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesSivKey) {
      return createAesSiv((AesSivKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  // We only allow 64-byte keys for AesSiv, because 32-byte keys might not provide 128-bit security
  // level in multi-user setting.
  private static final int KEY_SIZE_IN_BYTES = 64;

  private static DeterministicAead createAesSiv(AesSivKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "invalid key size: "
              + key.getParameters().getKeySizeBytes()
              + ". Valid keys must have "
              + KEY_SIZE_IN_BYTES
              + " bytes.");
    }
    return AesSiv.create(key);
  }
}
