// Copyright 2020 Google LLC
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

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.prf.internal.LegacyFullPrf;
import com.google.crypto.tink.prf.internal.WrappedPrfSet;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * PrfSetWrapper is the implementation of PrimitiveWrapper for the PrfSet primitive.
 *
 * <p>The returned primitive has instances of {@code Prf} for each key in the KeySet. The individual
 * Prf instances can then be used to compute psuedo-random sequences from the underlying key.
 */
@Immutable
public class PrfSetWrapper implements PrimitiveWrapper<Prf, PrfSet> {

  private static final PrfSetWrapper WRAPPER = new PrfSetWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Prf>
      LEGACY_FULL_PRF_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullPrf::create, LegacyProtoKey.class, Prf.class);

  @Override
  public PrfSet wrap(KeysetHandleInterface keysetHandle, PrimitiveFactory<Prf> factory)
      throws GeneralSecurityException {
    return WrappedPrfSet.create(keysetHandle, factory);
  }

  @Override
  public Class<PrfSet> getPrimitiveClass() {
    return PrfSet.class;
  }

  @Override
  public Class<Prf> getInputPrimitiveClass() {
    return Prf.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_PRF_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code PrfSetWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
