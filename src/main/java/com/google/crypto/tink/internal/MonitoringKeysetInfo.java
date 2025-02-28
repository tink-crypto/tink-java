// Copyright 2022 Google LLC
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
import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nullable;

/**
 * Immutable representation of a Keyset in a certain point in time for the purpose of monitoring
 * operations involving cryptographic keys.
 *
 * <p>Do not use. This API is not yet ready and may change or be removed.
 */
@Immutable
@Alpha
public final class MonitoringKeysetInfo {

  /** Description about each entry of the Keyset. */
  @Immutable
  public static final class Entry {
    private final Key key;
    private final KeyStatus status;
    private final int keyId;
    private final boolean isPrimary;

    public KeyStatus getStatus() {
      return status;
    }

    public int getId() {
      return keyId;
    }

    public Key getKey() {
      return key;
    }

    public boolean isPrimary() {
      return isPrimary;
    }

    private Entry(Key key, KeyStatus status, int keyId, boolean isPrimary) {
      this.key = key;
      this.status = status;
      this.keyId = keyId;
      this.isPrimary = isPrimary;
    }

    @Override
    public String toString() {
      return String.format("(status=%s, keyId=%s)", this.status, this.keyId);
    }
  }

  /** Builder */
  public static final class Builder {
    // builderEntries == null indicates that build has already been called and the builder is not
    // usable anymore.
    @Nullable private ArrayList<Entry> builderEntries = new ArrayList<>();
    @Nullable private Integer builderPrimaryKeyId = null;

    @CanIgnoreReturnValue
    public Builder addEntry(Key key, KeyStatus status, int keyId) {
      if (builderEntries == null) {
        throw new IllegalStateException("addEntry cannot be called after build()");
      }
      builderEntries.add(new Entry(key, status, keyId, false));
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPrimaryKeyId(int primaryKeyId) {
      if (builderEntries == null) {
        throw new IllegalStateException("setPrimaryKeyId cannot be called after build()");
      }
      builderPrimaryKeyId = primaryKeyId;
      return this;
    }

    private boolean verifyPrimaryAndSetToPrimary(int keyId) {
      for (int i = 0; i < builderEntries.size(); i++) {
        Entry entry = builderEntries.get(i);
        if (entry.getId() == keyId) {
          builderEntries.set(i, new Entry(entry.key, entry.status, entry.keyId, true));
          return true;
        }
      }
      return false;
    }

    /** Builds the MonitoringKeysetInfo object. The builder is not usable anymore afterwards. */
    public MonitoringKeysetInfo build() throws GeneralSecurityException {
      if (builderEntries == null) {
        throw new IllegalStateException("cannot call build() twice");
      }
      if (builderPrimaryKeyId != null) {
        // We allow the primary key to not be set. But if it is set, we verify that it is present in
        // the keyset. We also replace the entry with one which knows that it's the primary.
        if (!verifyPrimaryAndSetToPrimary(builderPrimaryKeyId.intValue())) {
          throw new GeneralSecurityException("primary key ID is not present in entries");
        }
      }
      MonitoringKeysetInfo output =
          new MonitoringKeysetInfo(
              Collections.unmodifiableList(builderEntries), builderPrimaryKeyId);
      // Collections.unmodifiableMap/List only gives an unmodifiable view of the underlying
      // collection. To make output immutable, we have to remove the reference to these collections.
      // This makes the builder unusable.
      builderEntries = null;
      return output;
    }
  }

  @SuppressWarnings("Immutable")
  private final List<Entry> entries;

  @Nullable private final Integer primaryKeyId;

  private MonitoringKeysetInfo(List<Entry> entries, Integer primaryKeyId) {
    this.entries = entries;
    this.primaryKeyId = primaryKeyId;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Entry getAt(int i) {
    return entries.get(i);
  }

  public int size() {
    return entries.size();
  }

  public Entry getPrimary() {
    for (int i = 0; i < size(); i++) {
      if (getAt(i).isPrimary()) {
        return getAt(i);
      }
    }
    throw new IllegalStateException("Keyset has no valid primary");
  }

  @Nullable
  public Integer getPrimaryKeyId() {
    return primaryKeyId;
  }

  @Override
  public String toString() {
    return String.format("(entries=%s, primaryKeyId=%s)", entries, primaryKeyId);
  }
}
