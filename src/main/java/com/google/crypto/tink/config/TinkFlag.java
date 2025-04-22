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

/**
 * Describes a change to Tink behavior.
 *
 * <p>A flag describes a change to behavior in Tink.
 *
 * <p>There are several use cases for flags.
 *
 * <p>The most common use cases is that flags are used to change change behavior of APIs in Tink.
 * The only way this is done is that an API which previously did some operation will be changed to
 * throw an exception (due to some validation error). The flag can then be used to fall back to the
 * legacy behavior where the input is accepted. For example, this can be done when parsing is made
 * stricter.
 *
 * <p>Another use case is that the flag makes validation less strict. This can be useful when one
 * wants to react to emergency. For example, suppose a Keyset has an AEAD key which is not a primary
 * and is of a key type which Tink does not understand. In this case it can be useful to ignore this
 * key.
 */
public interface TinkFlag {
  /**
   * Overrides the value to {@code t} for this flag.
   *
   * <p>Users can set this to enable different behavior.
   */
  public void setValue(boolean t);

  /**
   * Returns the current value of this flag.
   *
   * <p>This is typically only used within Tink to control behavior.
   */
  public boolean getValue();
}
