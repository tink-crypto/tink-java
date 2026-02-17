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

import com.google.crypto.tink.Annotations;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;

/**
 * Provides the basic interface for KeysetHandle.
 *
 * <p>This is useful in contexts where we want to have the API of KeysetHandle, but not the
 * dependencies.
 */
public interface KeysetHandleInterface {
  /** Provides the basic interface for KeysetHandle.Entry. */
  public interface Entry {
    Key getKey();

    KeyStatus getStatus();

    int getId();

    boolean isPrimary();
  }

  Entry getPrimary();

  int size();

  Entry getAt(int i);

  <T extends Annotations> T getAnnotationsOrNull(Class<T> t);
}
