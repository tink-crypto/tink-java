// Copyright 2025 Google LLC
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

import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Provides a map from prefix to arbitrary elements, allowing fast iteration over all elements whose
 * prefix matches a given {@code byte[]}.
 *
 * <p>To create a {@code PrefixMap}, the user adds pairs {@code (Prefix, Value)}. To query, the user
 * provides a {@code byte[]} and the map returns an unmodifiable list of matching values.
 *
 * <p>Currently supports prefixes of length 5 and 0. Matches with 5-byte prefixes are returned
 * before 0-byte (RAW) fallback prefixes.
 */
@Immutable
public final class PrefixMap<P> {
  private static final Bytes EMPTY_BYTES = Bytes.copyFrom(new byte[0]);

  /** Builder for {@link PrefixMap}. */
  public static class Builder<P> {
    /**
     * Adds a value for a given prefix.
     *
     * @param prefix the prefix bytes (must be 0 or 5 bytes)
     * @param primitive the primitive value
     */
    @CanIgnoreReturnValue
    public Builder<P> put(Bytes prefix, P primitive) throws GeneralSecurityException {
      Objects.requireNonNull(prefix, "prefix must be non-null");
      Objects.requireNonNull(primitive, "primitive must be non-null");
      if (prefix.size() != 0 && prefix.size() != 5) {
        throw new GeneralSecurityException("PrefixMap only supports 0 and 5 byte prefixes");
      }
      List<P> listForThisPrefix = entries.computeIfAbsent(prefix, k -> new ArrayList<>());
      listForThisPrefix.add(primitive);
      return this;
    }

    /** Builds an immutable {@link PrefixMap} with pre-merged prefix lists for fast dispatch. */
    public PrefixMap<P> build() {
      List<P> rawList = entries.get(EMPTY_BYTES);
      List<P> rawEntries =
          rawList != null
              ? Collections.unmodifiableList(new ArrayList<>(rawList))
              : Collections.emptyList();

      Map<Bytes, List<P>> precomputed = new HashMap<>();
      for (Map.Entry<Bytes, List<P>> entry : entries.entrySet()) {
        if (entry.getKey().size() == 5) {
          List<P> combined = new ArrayList<>(entry.getValue().size() + rawEntries.size());
          combined.addAll(entry.getValue());
          combined.addAll(rawEntries);
          precomputed.put(entry.getKey(), Collections.unmodifiableList(combined));
        }
      }
      return new PrefixMap<>(precomputed, rawEntries);
    }

    private final Map<Bytes, List<P>> entries = new HashMap<>();
  }

  /**
   * Returns an unmodifiable list of all values matching the prefix of {@code text}.
   *
   * <p>The matches with 5-byte prefixes are returned first, followed by 0-byte (RAW) matches.
   * Within a given prefix length, values are returned in insertion order.
   */
  public List<P> getAllWithMatchingPrefix(byte[] text) {
    Objects.requireNonNull(text, "text must be non-null");
    if (entries.isEmpty() || text.length < 5) {
      return rawEntries;
    }
    List<P> matched = entries.get(Bytes.copyFrom(text, 0, 5));
    return matched != null ? matched : rawEntries;
  }

  private PrefixMap(Map<Bytes, List<P>> entries, List<P> rawEntries) {
    this.entries = Collections.unmodifiableMap(entries);
    this.rawEntries = rawEntries;
  }

  @SuppressWarnings("Immutable")
  private final Map<Bytes, List<P>> entries;
  @SuppressWarnings("Immutable")
  private final List<P> rawEntries;
}
