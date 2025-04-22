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

package com.google.crypto.tink.config;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Contains Booleans which change Tink behavior globally.
 *
 * <p>Note: within Google, except for Android, Tink uses a different version of this file which uses
 * a Google-only flag mechanism.
 */
public final class GlobalTinkFlags {
  /**
   * If true, Tink validates keysets when parsing a KeysetHandle. This means that keysets which have
   * repeated key ids, keysets without valid primary, and keysets which have invalid 'KeyStatusType'
   * are rejected.
   *
   * <ul>
   *   <li>Introduced in: Tink 1.18.
   *   <li>Earliest change to {@code true}: Tink 2.0
   *   <li>Earliest removal: Tink 3.0
   * </ul>
   */
  public static final TinkFlag validateKeysetsOnParsing = new TinkFlagImpl(false);

  private static class TinkFlagImpl implements TinkFlag {
    private final AtomicBoolean b;

    TinkFlagImpl(boolean b) {
      this.b = new AtomicBoolean(b);
    }

    @Override
    public boolean getValue() {
      return b.get();
    }

    @Override
    public void setValue(boolean t) {
      b.set(t);
    }
  }

  private GlobalTinkFlags() {}
}
