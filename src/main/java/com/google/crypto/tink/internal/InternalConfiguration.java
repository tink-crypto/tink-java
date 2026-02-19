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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.KeysetHandleInterface;
import java.security.GeneralSecurityException;

/**
 * Abstract class representing the real configuration API, i.e. all algorithms that Tink
 * understands. Internal. Users should not access these methods since the operations are to be used
 * by internal KeysetHandle operations only.
 */
public abstract class InternalConfiguration implements Configuration {
  /**
   * Creates a primitive from a KeysetHandle.
   *
   * @throws GeneralSecurityException if the wrapper for the provided pair (input class, wrapped
   *     class) is not registered
   */
  public abstract <P> P wrap(KeysetHandleInterface keysetHandle, Class<P> clazz)
      throws GeneralSecurityException;

  public static InternalConfiguration createFromPrimitiveRegistry(PrimitiveRegistry registry) {
    return new InternalConfigurationImpl(registry);
  }

  @Override
  public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
      throws GeneralSecurityException {
    return wrap(keysetHandle, clazz);
  }

  /**
   * Implementation of the configuration API.
   */
  private static class InternalConfigurationImpl extends InternalConfiguration {
    /**
     * Immutable registry instance.
     */
    private final PrimitiveRegistry registry;

    private InternalConfigurationImpl(PrimitiveRegistry registry) {
      this.registry = registry;
    }

    @Override
    public <P> P wrap(KeysetHandleInterface keysetHandle, Class<P> clazz)
        throws GeneralSecurityException {
      return registry.wrap(keysetHandle, clazz);
    }
  }
}
