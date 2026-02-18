// Copyright 2023 Google LLC
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

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.errorprone.annotations.DoNotCall;
import java.security.GeneralSecurityException;

/**
 * Represents the configuration as currently specified by the registry. That is, this configuration
 * is just a thin layer forwarding calls to the global {@link com.google.crypto.tink.Registry}.
 *
 * <p>Because the global {@link com.google.crypto.tink.Registry} changes when user code adds to it,
 * using this class is not recommended.
 */
public final class RegistryConfiguration extends InternalConfiguration {
  // Returns the singleton instance of RegistryConfiguration.
  public static RegistryConfiguration get() {
    return CONFIG;
  }

  private static final RegistryConfiguration CONFIG = new RegistryConfiguration();

  private RegistryConfiguration() {}

  @Override
  public <P> P wrap(KeysetHandleInterface keysetHandle, Class<P> clazz)
      throws GeneralSecurityException {
    return MutablePrimitiveRegistry.globalInstance().wrap(keysetHandle, clazz);
  }

  /**
   * Do not call.
   *
   * <p>We shadow the function {@code createFromPrimitiveRegistry} here so that one cannot invoke
   * the static function in the superclass by writing {@code
   * RegistryConfiguration.createFromPrimitiveRegistry}.
   */
  @DoNotCall
  public static InternalConfiguration createFromPrimitiveRegistry(PrimitiveRegistry registry) {
    throw new UnsupportedOperationException(
        "Cannot create RegistryConfiguration from a PrimitiveRegistry");
  }
}
