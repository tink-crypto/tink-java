// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.RegistryConfiguration;
import java.security.GeneralSecurityException;

/**
 * Deprecated class to create {@code Mac} primitives. Instead of using this class, call {@code
 * keysetHandle.getPrimitive(MacConfig2026.get(), Mac.class)} (or {@code
 * keysetHandle.getPrimitive(TinkConfig2026.get(), Mac.class)}).
 *
 * <p>Alternatively, if you rely on global registration (via {@code MacConfig.register()}, {@code
 * HybridConfig.register()}, {@code AeadConfig.register()}, or {@code TinkConfig.register()}), call
 * {@code keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class)}.
 *
 * @deprecated Use {@code keysetHandle.getPrimitive(MacConfig2026.get(), Mac.class)} instead.
 * @since 1.0.0
 */
@Deprecated
public final class MacFactory {
  /**
   * @return a Mac primitive from a {@code keysetHandle}.
   * @deprecated Use {@code keysetHandle.getPrimitive(MacConfig2026.get(), Mac.class)} instead.
   */
  @Deprecated
  public static Mac getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    MacWrapper.register();
    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class);
  }

  private MacFactory() {}
}
