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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.XAesGcm;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import java.security.GeneralSecurityException;

/**
 * AeadConfigurationV1 contains the following algorithms for Aead:
 *
 * <ul>
 *   <li>AesCtrHmac
 *   <li>AesGcm
 *   <li>AesGcmSiv
 *   <li>AesEax
 *   <li>ChaCha20Poly1305
 *   <li>XChaCha20Poly1305
 *   <li>XAesGcm
 * </ul>
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class AeadConfigurationV1 {
  private AeadConfigurationV1() {}

  private static final AeadWrapper WRAPPER = new AeadWrapper();
  private static final Configuration CONFIGURATION = create();

  static Aead createAead(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesCtrHmacAeadKey) {
      return EncryptThenAuthenticate.create((AesCtrHmacAeadKey) key);
    }
    if (key instanceof AesGcmKey) {
      return AesGcmJce.create((AesGcmKey) key);
    }
    if (key instanceof AesGcmSivKey) {
      return AesGcmSiv.create((AesGcmSivKey) key);
    }
    if (key instanceof AesEaxKey) {
      return AesEaxJce.create((AesEaxKey) key);
    }
    if (key instanceof ChaCha20Poly1305Key) {
      return createChaCha20Poly1305((ChaCha20Poly1305Key) key);
    }
    if (key instanceof XChaCha20Poly1305Key) {
      return createXChaCha20Poly1305((XChaCha20Poly1305Key) key);
    }
    if (key instanceof XAesGcmKey) {
      return XAesGcm.create((XAesGcmKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz != Aead.class) {
          throw new GeneralSecurityException("AeadConfigurationV1 can only create AEADs");
        }
        return clazz.cast(WRAPPER.wrap(keysetHandle, AeadConfigurationV1::createAead));
      }
    };
  }

  /** Returns an instance of the {@code AeadConfigurationV1}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant AeadConfigurationV1 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static Aead createChaCha20Poly1305(ChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (ChaCha20Poly1305Jce.isSupported()) {
      return ChaCha20Poly1305Jce.create(key);
    }
    return ChaCha20Poly1305.create(key);
  }

  private static Aead createXChaCha20Poly1305(XChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (XChaCha20Poly1305Jce.isSupported()) {
      return XChaCha20Poly1305Jce.create(key);
    }
    return XChaCha20Poly1305.create(key);
  }
}
