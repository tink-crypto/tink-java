// Copyright 2017 Google LLC
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
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.aead.internal.LegacyFullAead;
import com.google.crypto.tink.aead.internal.WrappedAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import java.security.GeneralSecurityException;

/**
 * AeadWrapper is the implementation of SetWrapper for the Aead primitive.
 *
 * <p>Key rotation works as follows: each ciphertext is prefixed with the keyId. When decrypting, we
 * first try all primitives whose keyId starts with the prefix of the ciphertext. If none of these
 * succeed, we try the raw primitives. If any succeeds, we return the ciphertext, otherwise we
 * simply throw a GeneralSecurityException.
 */
public class AeadWrapper implements PrimitiveWrapper<Aead, Aead> {
  private static final AeadWrapper WRAPPER = new AeadWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Aead>
      LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullAead::create, LegacyProtoKey.class, Aead.class);

  AeadWrapper() {}

  @Override
  public Aead wrap(
      KeysetHandleInterface keysetHandle,
      PrimitiveFactory<Aead> factory)
      throws GeneralSecurityException {
    return WrappedAead.create(keysetHandle, factory);
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }

  @Override
  public Class<Aead> getInputPrimitiveClass() {
    return Aead.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code AeadWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
