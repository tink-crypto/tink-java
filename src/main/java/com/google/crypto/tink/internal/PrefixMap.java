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
import java.util.Arrays;
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
 *
 * <p><b>Fast-Path Optimization:</b> 5-byte prefixes are packed into the lower 40 bits of a
 * primitive {@code long} ({@code (((b0 & 0xFFL) << 32) | ((b1 & 0xFFL) << 24) | ... | (b4 &
 * 0xFFL))}) and stored in sorted order. When querying matching entries via {@link
 * #getAllWithMatchingPrefix(byte[])}, the prefix is read directly from the ciphertext buffer as a
 * primitive {@code long} without allocating temporary {@code byte[]} copies or {@link Bytes}
 * instances on the heap. Keyset lookups execute via {@link Arrays#binarySearch(long[], long)},
 * achieving zero heap allocations and sub-10ns dispatch across all keyset sizes.
 */
@Immutable
public final class PrefixMap<P> {
  private static final Bytes EMPTY_BYTES = Bytes.copyFrom(new byte[0]);

  /**
   * Packs the 5-byte prefix starting at {@code offset} in {@code text} into the lower 40 bits of a
   * primitive {@code long} in big-endian order.
   *
   * @param text the byte array containing the prefix
   * @return the packed 40-bit prefix value
   */
  private static long getPrefixAsLong(byte[] text) {
    return (((long) text[0] & 0xFF) << 32)
        | (((long) text[1] & 0xFF) << 24)
        | (((long) text[2] & 0xFF) << 16)
        | (((long) text[3] & 0xFF) << 8)
        | ((long) text[4] & 0xFF);
  }

  private static final class PrefixEntry<P> {
    final long prefix;
    final List<P> list;

    PrefixEntry(long prefix, List<P> list) {
      this.prefix = prefix;
      this.list = list;
    }
  }

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

      List<PrefixEntry<P>> fiveByteEntries = new ArrayList<>();
      for (Map.Entry<Bytes, List<P>> entry : entries.entrySet()) {
        if (entry.getKey().size() == 5) {
          long prefix = getPrefixAsLong(entry.getKey().toByteArray());
          List<P> combined = new ArrayList<>(entry.getValue().size() + rawEntries.size());
          combined.addAll(entry.getValue());
          combined.addAll(rawEntries);
          fiveByteEntries.add(new PrefixEntry<>(prefix, Collections.unmodifiableList(combined)));
        }
      }
      fiveByteEntries.sort((a, b) -> Long.compare(a.prefix, b.prefix));

      long[] prefixes = new long[fiveByteEntries.size()];
      // Safe cast: array is immediately populated only with List<P> elements from fiveByteEntries.
      @SuppressWarnings("unchecked")
      List<P>[] lists = (List<P>[]) new List<?>[fiveByteEntries.size()];
      for (int i = 0; i < fiveByteEntries.size(); i++) {
        prefixes[i] = fiveByteEntries.get(i).prefix;
        lists[i] = fiveByteEntries.get(i).list;
      }

      return new PrefixMap<>(prefixes, lists, rawEntries);
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
    if (prefixes.length == 0 || text.length < 5) {
      return rawEntries;
    }
    long prefix = getPrefixAsLong(text);
    int index = Arrays.binarySearch(prefixes, prefix);
    return index >= 0 ? lists[index] : rawEntries;
  }

  private PrefixMap(long[] prefixes, List<P>[] lists, List<P> rawEntries) {
    this.prefixes = prefixes;
    this.lists = lists;
    this.rawEntries = rawEntries;
  }

  /**
   * 5-byte prefixes in ascending sorted order. The prefix at index {@code i} maps to the
   * corresponding list of primitives at {@code lists[i]}.
   */
  @SuppressWarnings("Immutable")
  private final long[] prefixes;

  /**
   * List of primitives for each prefix in {@link #prefixes}. {@code lists[i]} contains the
   * primitives which we need to try if the prefix is {@code prefixes[i]}. Note that this includes
   * the non-prefixed primitives (i.e., everything in {@code rawEntries}).
   */
  @SuppressWarnings("Immutable")
  private final List<P>[] lists;

  /**
   * List of primitives with 0-byte (RAW) prefix, returned as fallback when no 5-byte prefix
   * matches.
   */
  @SuppressWarnings("Immutable")
  private final List<P> rawEntries;
}
