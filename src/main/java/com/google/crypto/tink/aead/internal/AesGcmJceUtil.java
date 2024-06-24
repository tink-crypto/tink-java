// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Validators;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Helper functions for AES-GCM using JCE. */
public final class AesGcmJceUtil {

  // All instances of this class use a 12-byte IV and a 16-byte tag.
  public static final int IV_SIZE_IN_BYTES = 12;
  public static final int TAG_SIZE_IN_BYTES = 16;

  private static final ThreadLocal<Cipher> localCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  /** Returns a thread-local instance of the AES-GCM cipher. */
  public static Cipher getThreadLocalCipher() {
    return localCipher.get();
  }

  public static SecretKey getSecretKey(final byte[] key) throws GeneralSecurityException {
    Validators.validateAesKeySize(key.length);
    return new SecretKeySpec(key, "AES");
  }

  public static AlgorithmParameterSpec getParams(final byte[] iv) {
    return getParams(iv, 0, iv.length);
  }

  public static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len) {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel <= 19) {
      // GCMParameterSpec should always be present in Java 7 or newer, but it's unsupported on
      // Android devices with API level <= 19. Fortunately, if a modern copy of Conscrypt is present
      // (either through GMS Core or bundled with the app) we can initialize the cipher with just an
      // IvParameterSpec. It will use a tag size of 128 bits.
      //
      // Note that API level 19 is not supported anymore by Tink, and we don't run tests on it
      // anymore.
      return new IvParameterSpec(buf, offset, len);
    }
    return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, buf, offset, len);
  }

  private AesGcmJceUtil() {}
}
