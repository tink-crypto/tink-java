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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Provides a map from prefix to arbitrary element, allowing to iterate over all elements whose
 * prefixes matches a given {@code byte[]}.
 *
 * <p>To create a {@code PrefixMap}, the user adds pairs {@code (Prefix, Value)}, as in a map. To
 * query, the user provides a {@code byte[]} and the map will allow to iterate over all values which
 * were added with a prefix of the given {@code byte[]}.
 *
 * <p>Currently only supports prefixes of length 5 and 0.
 */
@Immutable
public final class PrefixMap<P> {
  private static final Bytes EMPTY_BYTES = Bytes.copyFrom(new byte[0]);

  /** Builder for PrefixMap. */
  public static class Builder<P> {
    /**
     * Adds a value for a given prefix.
     *
     * <p>{@code prefix.size()} has to be 0 or 5.
     */
    @CanIgnoreReturnValue
    public Builder<P> put(Bytes prefix, P primitive) throws GeneralSecurityException {
      if (prefix.size() != 0 && prefix.size() != 5) {
        throw new GeneralSecurityException("PrefixMap only supports 0 and 5 byte prefixes");
      }
      List<P> listForThisPrefix;
      if (entries.containsKey(prefix)) {
        listForThisPrefix = entries.get(prefix);
      } else {
        listForThisPrefix = new ArrayList<P>();
        entries.put(prefix, listForThisPrefix);
      }
      listForThisPrefix.add(primitive);
      return this;
    }

    public PrefixMap<P> build() {
      return new PrefixMap<P>(entries);
    }

    private final Map<Bytes, List<P>> entries = new HashMap<>();
  }

  private static class ConcatenatedIterator<P> implements Iterator<P> {

    private ConcatenatedIterator(Iterator<P> it0, Iterator<P> it1) {
      this.it0 = it0;
      this.it1 = it1;
    }

    @Override
    public boolean hasNext() {
      return it0.hasNext() || it1.hasNext();
    }

    @Override
    public P next() {
      if (it0.hasNext()) {
        return it0.next();
      }
      return it1.next();
    }

    private final Iterator<P> it0;
    private final Iterator<P> it1;
  }

  /**
   * Provides an iterable which goves over all values which were added with a prefix of the given
   * {@code text}.
   *
   * <p>The matches with the longest prefixes are returned first. Within a given length, the values
   * are returned in the order they were provided in the builder.
   */
  public Iterable<P> getAllWithMatchingPrefix(byte[] text) {
    List<P> zeroByteEntriesOrNull = entries.get(EMPTY_BYTES);
    List<P> fiveByteEntriesOrNull =
        text.length >= 5 ? entries.get(Bytes.copyFrom(text, 0, 5)) : null;
    if (zeroByteEntriesOrNull == null && fiveByteEntriesOrNull == null) {
      return new ArrayList<P>();
    }
    if (zeroByteEntriesOrNull == null) {
      return fiveByteEntriesOrNull;
    }
    if (fiveByteEntriesOrNull == null) {
      return zeroByteEntriesOrNull;
    }
    return new Iterable<P>() {
      @Override
      public Iterator<P> iterator() {
        return new ConcatenatedIterator<P>(
            fiveByteEntriesOrNull.iterator(), zeroByteEntriesOrNull.iterator());
      }
    };
  }

  private PrefixMap(Map<Bytes, List<P>> entries) {
    this.entries = entries;
  }

  @SuppressWarnings("Immutable")
  private final Map<Bytes, List<P>> entries;
}
