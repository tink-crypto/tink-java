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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.signature.internal.LegacyFullSign;
import com.google.crypto.tink.signature.internal.WrappedPublicKeySign;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<PublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
public class PublicKeySignWrapper implements PrimitiveWrapper<PublicKeySign, PublicKeySign> {

  private static final PublicKeySignWrapper WRAPPER = new PublicKeySignWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, PublicKeySign>
      LEGACY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullSign::create, LegacyProtoKey.class, PublicKeySign.class);

  PublicKeySignWrapper() {}

  @Override
  public PublicKeySign wrap(
      KeysetHandleInterface keysetHandle, PrimitiveFactory<PublicKeySign> factory)
      throws GeneralSecurityException {
    return WrappedPublicKeySign.create(keysetHandle, factory);
  }

  @Override
  public Class<PublicKeySign> getPrimitiveClass() {
    return PublicKeySign.class;
  }

  @Override
  public Class<PublicKeySign> getInputPrimitiveClass() {
    return PublicKeySign.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeySign}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code PublicKeySignWrapper} to the provided
   * {@code PrimitiveRegistry#Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
