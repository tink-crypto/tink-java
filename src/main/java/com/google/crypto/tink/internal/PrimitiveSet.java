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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;

/**
 * A legacy class which can now create objects of type KeysetHandleInterface.
 *
 * <p>PrimitiveSet used to be a class which contained the same information as a Keyset and
 * primitives for each key. In a refactoring it was removed, and is now testonly. It should not be
 * used in new code.
 */
public final class PrimitiveSet {
  /** A single entry in the set. */
  public static final class Entry implements KeysetHandleInterface.Entry {
    private final KeyStatus status;
    private final int keyId;
    private final Key key;
    private final boolean isPrimary;

    private Entry(KeyStatus status, int keyId, Key key, boolean isPrimary) {
      this.status = status;
      this.keyId = keyId;
      this.key = key;
      this.isPrimary = isPrimary;
    }

    @Override
    public KeyStatus getStatus() {
      return status;
    }

    @Override
    public int getId() {
      return keyId;
    }

    @Override
    public Key getKey() {
      return key;
    }

    @Nullable
    public Parameters getParameters() {
      if (key == null) {
        return null;
      }
      return key.getParameters();
    }

    @Override
    public boolean isPrimary() {
      return isPrimary;
    }
  }

  private static void storeEntryInPrimitiveSet(
      KeysetHandleInterface.Entry entry, List<KeysetHandleInterface.Entry> entriesInKeysetOrder) {
    entriesInKeysetOrder.add(entry);
  }

  /** Implements KeysetHandle. */
  private static class KeysetHandleImpl implements KeysetHandleInterface {
    private final List<KeysetHandleInterface.Entry> entriesInKeysetOrder;
    private final KeysetHandleInterface.Entry primary;

    public KeysetHandleImpl(
        List<KeysetHandleInterface.Entry> entriesInKeysetOrder,
        KeysetHandleInterface.Entry primary) {
      this.entriesInKeysetOrder = entriesInKeysetOrder;
      this.primary = primary;
    }

    @Override
    public KeysetHandleInterface.Entry getPrimary() {
      return primary;
    }

    @Override
    public int size() {
      return entriesInKeysetOrder.size();
    }

    @Override
    public KeysetHandleInterface.Entry getAt(int i) {
      return entriesInKeysetOrder.get(i);
    }
  }

  public KeysetHandleInterface getKeysetHandle() {
    return keysetHandle;
  }

  private final KeysetHandleInterface keysetHandle;

  private PrimitiveSet(KeysetHandleInterface keysetHandle) {
    this.keysetHandle = keysetHandle;
  }

  /** Builds an immutable PrimitiveSet. This is the prefered way to construct a PrimitiveSet. */
  public static class Builder {

    // primitives == null indicates that build has been called and the builder can't be used
    // anymore.
    private List<KeysetHandleInterface.Entry> entriesInKeysetOrder = new ArrayList<>();
    private KeysetHandleInterface.Entry primary;

    @CanIgnoreReturnValue
    private Builder addEntry(Key key, int keyId, boolean asPrimary)
        throws GeneralSecurityException {
      if (entriesInKeysetOrder == null) {
        throw new IllegalStateException("addEntry cannot be called after build");
      }
      KeysetHandleInterface.Entry entry =
          new Entry(
              // We checked before calling addEntry that we allow only ENABLED.
              KeyStatus.ENABLED, keyId, key, asPrimary);
      storeEntryInPrimitiveSet(entry, entriesInKeysetOrder);
      if (asPrimary) {
        if (this.primary != null) {
          throw new IllegalStateException("you cannot set two primary primitives");
        }
        this.primary = entry;
      }
      return this;
    }

    /**
     * Adds a non-primary primitive.
     *
     * <p>The caller must make sure that the {@code fullPrimitive} is a full primitive constructed
     * from key, and that {@code protoKey} contains the same key as {@code fullPrimitive}.
     */
    @CanIgnoreReturnValue
    public Builder add(Key key, Keyset.Key protoKey) throws GeneralSecurityException {
      if (protoKey.getStatus() != KeyStatusType.ENABLED) {
        // Note: ENABLED is hard coded in addEntry.
        throw new GeneralSecurityException("only ENABLED key is allowed");
      }
      return addEntry(key, protoKey.getKeyId(), false);
    }

    /**
     * Adds the primary primitive. This should be called exactly once per PrimitiveSet.
     *
     * <p>The caller must make sure that the {@code fullPrimitive} is a full primitive constructed
     * from key, and that {@code protoKey} contains the same key as {@code fullPrimitive}.
     */
    @CanIgnoreReturnValue
    public Builder addPrimary(Key key, Keyset.Key protoKey) throws GeneralSecurityException {
      if (protoKey.getStatus() != KeyStatusType.ENABLED) {
        // Note: ENABLED is hard coded in addEntry.
        throw new GeneralSecurityException("only ENABLED key is allowed");
      }
      return addEntry(key, protoKey.getKeyId(), true);
    }

    public PrimitiveSet build() throws GeneralSecurityException {
      if (entriesInKeysetOrder == null) {
        throw new IllegalStateException("build cannot be called twice");
      }
      // Note that we currently don't enforce that primary must be set.
      PrimitiveSet output = new PrimitiveSet(new KeysetHandleImpl(entriesInKeysetOrder, primary));
      this.entriesInKeysetOrder = null;
      return output;
    }

    private Builder() {}
  }

  public static Builder newBuilder() {
    return new Builder();
  }
}
