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

package com.google.crypto.tink;

/**
 * Provides the basic interface for KeysetHandle.
 *
 * <p>This is useful in contexts where we want to have the API of KeysetHandle, but not the
 * dependencies.
 */
public interface KeysetHandleInterface {
  /** Provides the basic interface for KeysetHandle.Entry. */
  public interface Entry {
    /** Returns the key for this entry. */
    Key getKey();

    /** Returns the key status for this entry. */
    KeyStatus getStatus();

    /** Returns the ID for this entry. */
    int getId();

    /** True if this entry is the unique primary in a keyset. */
    boolean isPrimary();
  }

  /** Returns the unique primary entry of the keyset. */
  Entry getPrimary();

  /** Returns the number of entries in this keyset. */
  int size();

  /**
   * Returns the entry at position i.
   *
   * @throws IndexOutOfBoundsException if i < 0 or i >= size();
   */
  Entry getAt(int i);

  /**
   * Returns annotations which could previously be added with {@code
   * KeysetHandleBuilder.addAnnotations();}
   */
  <T extends Annotations> T getAnnotationsOrNull(Class<T> t);
}
