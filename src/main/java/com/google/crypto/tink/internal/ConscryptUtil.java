// Copyright 2024 Google LLC
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import javax.annotation.Nullable;

/** Utility functions for Conscrypt. */
public final class ConscryptUtil {

  private static final String[] conscryptProviderNames =
      new String[] {"GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt"};

  @Nullable
  public static Provider providerOrNull() {
    for (String providerName : conscryptProviderNames) {
      Provider provider = Security.getProvider(providerName);
      if (provider != null) {
        return provider;
      }
    }
    return null;
  }

  /**
   * Tries to get the Conscrypt provider using reflection.
   *
   * <p>Note that this will typically fail on Android because ProGuard renames all class and
   * method names. However, on Android, Conscrypt is installed by default and so this code is not
   * executed.
   */
  @Nullable
  public static Provider providerWithReflectionOrNull() {
    try {
      Class<?> conscrypt = Class.forName("org.conscrypt.Conscrypt");
      Method getProvider = conscrypt.getMethod("newProvider");
      return (Provider) getProvider.invoke(null);
    } catch (ClassNotFoundException
        | NoSuchMethodException
        | IllegalArgumentException
        | InvocationTargetException
        | IllegalAccessException e) {
      return null;
    }
  }

  public static final boolean isConscryptProvider(Provider provider) {
    String providerName = provider.getName();
    return providerName.equals("GmsCore_OpenSSL")
        || providerName.equals("AndroidOpenSSL")
        || providerName.equals("Conscrypt");
  }

  private ConscryptUtil() {}
}
