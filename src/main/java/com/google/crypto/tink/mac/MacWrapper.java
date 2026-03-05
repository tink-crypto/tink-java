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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.mac.internal.LegacyFullMac;
import com.google.crypto.tink.mac.internal.WrappedMac;
import java.security.GeneralSecurityException;

/**
 * MacWrapper is the implementation of PrimitiveWrapper for the Mac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To compute a MAC tag,
 * it uses the primary key in the keyset, and prepends to the tag a certain prefix associated with
 * the primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select
 * the right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class MacWrapper implements PrimitiveWrapper<Mac, Mac> {
  private static final MacWrapper WRAPPER = new MacWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Mac>
      LEGACY_FULL_MAC_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullMac::create, LegacyProtoKey.class, Mac.class);

  MacWrapper() {}

  @Override
  public Mac wrap(KeysetHandleInterface keysetHandle, PrimitiveFactory<Mac> factory)
      throws GeneralSecurityException {
    return WrappedMac.create(keysetHandle, factory);
  }

  @Override
  public Class<Mac> getPrimitiveClass() {
    return Mac.class;
  }

  @Override
  public Class<Mac> getInputPrimitiveClass() {
    return Mac.class;
  }

  static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_MAC_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code MacWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
