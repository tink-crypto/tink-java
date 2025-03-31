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
 * A container class for a set of primitives -- implementations of cryptographic primitives offered
 * by Tink.
 *
 * <p>It provides also additional properties for the primitives it holds. In particular, one of the
 * primitives in the set can be distinguished as "the primary" one.
 *
 * <p>PrimitiveSet is an auxiliary class used for supporting key rotation: primitives in a set
 * correspond to keys in a keyset. Users will usually work with primitive instances, which
 * essentially wrap primitive sets. For example an instance of an Aead-primitive for a given keyset
 * holds a set of Aead-primitives corresponding to the keys in the keyset, and uses the set members
 * to do the actual crypto operations: to encrypt data the primary Aead-primitive from the set is
 * used, and upon decryption the ciphertext's prefix determines the id of the primitive from the
 * set.
 */
public final class PrimitiveSet {
  public static KeysetHandleInterface legacyRemoveNonEnabledKeys(KeysetHandleInterface input)
      throws GeneralSecurityException {
    PrimitiveSet.Builder builder = PrimitiveSet.newBuilder();
    for (int i = 0; i < input.size(); ++i) {
      KeysetHandleInterface.Entry entry = input.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        builder.addEntry(entry.getKey(), entry.getId(), entry.isPrimary());
      }
    }
    return builder.build().getKeysetHandle();
  }

  /**
   * A single entry in the set. In addition to the actual primitive it holds also some extra
   * information about the primitive.
   */
  public static final class Entry implements KeysetHandleInterface.Entry {
    // The status of the key represented by the primitive. Currently always equal to "ENABLED".
    private final KeyStatus status;
    // The id of the key.
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

  /**
   * Implements KeysetHandle based on the information available in PrimitiveSet.
   *
   * <p>Note: in the future we will simply pass in the actual KeysetHandle when constructing the
   * primitive set, and not build a new one here.
   *
   * <p>Note: this class is not static, and hence always has a pointer to the primitive set.
   */
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

  /** Creates an immutable PrimitiveSet. It is used by the Builder. */
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
