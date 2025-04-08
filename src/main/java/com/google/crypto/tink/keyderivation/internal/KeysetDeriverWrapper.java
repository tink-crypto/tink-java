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
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/** Knows how to implement a KeysetDeriver object from KeyDeriver objects. */
public final class KeysetDeriverWrapper implements PrimitiveWrapper<KeyDeriver, KeysetDeriver> {

  private static class DeriverWithId {
    DeriverWithId(KeyDeriver deriver, int id, boolean isPrimary) {
      this.deriver = deriver;
      this.id = id;
      this.isPrimary = isPrimary;
    }

    final KeyDeriver deriver;
    final int id;
    final boolean isPrimary;
  }

  private static final KeysetDeriverWrapper WRAPPER = new KeysetDeriverWrapper();

  private static void validate(KeysetHandleInterface keysetHandle) throws GeneralSecurityException {
    if (keysetHandle.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedKeysetDeriver implements KeysetDeriver {
    @SuppressWarnings("Immutable")
    private final List<DeriverWithId> derivers;

    private WrappedKeysetDeriver(List<DeriverWithId> derivers) {
      this.derivers = derivers;
    }

    private static KeysetHandle.Builder.Entry deriveAndGetEntry(
        byte[] salt, DeriverWithId deriverWithId) throws GeneralSecurityException {
      if (deriverWithId.deriver == null) {
        throw new GeneralSecurityException(
            "Primitive set has non-full primitives -- this is probably a bug");
      }
      Key key = deriverWithId.deriver.deriveKey(salt);
      KeysetHandle.Builder.Entry result = KeysetHandle.importKey(key);
      result.withFixedId(deriverWithId.id);
      if (deriverWithId.isPrimary) {
        result.makePrimary();
      }
      return result;
    }

    @Override
    public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
      KeysetHandle.Builder builder = KeysetHandle.newBuilder();
      for (DeriverWithId deriverWithId : derivers) {
        builder.addEntry(deriveAndGetEntry(salt, deriverWithId));
      }
      return builder.build();
    }
  }

  KeysetDeriverWrapper() {}

  @Override
  public KeysetDeriver wrap(
      KeysetHandleInterface keysetHandle,
      MonitoringAnnotations annotations,
      PrimitiveFactory<KeyDeriver> factory)
      throws GeneralSecurityException {
    validate(keysetHandle);
    List<DeriverWithId> derivers = new ArrayList<>(keysetHandle.size());
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        derivers.add(new DeriverWithId(factory.create(entry), entry.getId(), entry.isPrimary()));
      }
    }

    return new WrappedKeysetDeriver(derivers);
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
