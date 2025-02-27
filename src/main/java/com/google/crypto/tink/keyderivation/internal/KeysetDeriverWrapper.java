// Copyright 2023 Google LLC
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

package com.google.crypto.tink.keyderivation.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/** */
public final class KeysetDeriverWrapper implements PrimitiveWrapper<KeyDeriver, KeysetDeriver> {

  private static final KeysetDeriverWrapper WRAPPER = new KeysetDeriverWrapper();

  private static void validate(KeysetHandleInterface keysetHandle) throws GeneralSecurityException {
    if (keysetHandle.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedKeysetDeriver implements KeysetDeriver {
    @SuppressWarnings("Immutable")
    private final PrimitiveSet<KeyDeriver> primitiveSet;

    private WrappedKeysetDeriver(PrimitiveSet<KeyDeriver> primitiveSet) {
      this.primitiveSet = primitiveSet;
    }

    private static KeysetHandle.Builder.Entry deriveAndGetEntry(
        byte[] salt, KeysetHandleInterface.Entry entry, KeyDeriver deriver, int primaryKeyId)
        throws GeneralSecurityException {
      if (deriver == null) {
        throw new GeneralSecurityException(
            "Primitive set has non-full primitives -- this is probably a bug");
      }
      Key key = deriver.deriveKey(salt);
      KeysetHandle.Builder.Entry result = KeysetHandle.importKey(key);
      result.withFixedId(entry.getId());
      if (entry.getId() == primaryKeyId) {
        result.makePrimary();
      }
      return result;
    }

    @Override
    public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
      KeysetHandle.Builder builder = KeysetHandle.newBuilder();
      KeysetHandleInterface keysetHandleFromPrimitiveSet = primitiveSet.getKeysetHandle();
      for (int i = 0; i < keysetHandleFromPrimitiveSet.size(); i++) {
        KeysetHandleInterface.Entry entry = keysetHandleFromPrimitiveSet.getAt(i);
        KeyDeriver deriver = primitiveSet.getPrimitiveForEntry(entry);
        builder.addEntry(
            deriveAndGetEntry(
                salt, entry, deriver, keysetHandleFromPrimitiveSet.getPrimary().getId()));
      }
      return builder.build();
    }
  }

  KeysetDeriverWrapper() {}

  @Override
  public KeysetDeriver wrap(final PrimitiveSet<KeyDeriver> primitiveSet)
      throws GeneralSecurityException {
    validate(primitiveSet.getKeysetHandle());
    return new WrappedKeysetDeriver(primitiveSet);
  }

  @Override
  public Class<KeysetDeriver> getPrimitiveClass() {
    return KeysetDeriver.class;
  }

  @Override
  public Class<KeyDeriver> getInputPrimitiveClass() {
    return KeyDeriver.class;
  }

  /** Registers this wrapper with Tink, allowing to use the primitive. */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
  }
}
