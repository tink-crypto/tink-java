// Copyright 2026 Google LLC
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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/** ProtoBasedConfigurationBuilder builds an internal {@link Configuration} instance. */
public final class ProtoBasedConfigurationBuilder {

  private static final class InternalProtoBasedConfiguration implements Configuration {
    private final Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators;

    InternalProtoBasedConfiguration(Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators) {
      this.keyCreators = Collections.unmodifiableMap(new HashMap<>(keyCreators));
    }

    @Override
    public Key createKey(Parameters parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
      @SuppressWarnings("unchecked") // We create the map so that it satisfies this.
      KeyCreator<Parameters> creator =
          (KeyCreator<Parameters>) keyCreators.get(parameters.getClass());
      if (creator == null) {
        throw new GeneralSecurityException("No KeyCreator registered for " + parameters.getClass());
      }
      return creator.createKey(parameters, idRequirement);
    }
  }

  private final Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators = new HashMap<>();

  public ProtoBasedConfigurationBuilder() {}

  @CanIgnoreReturnValue
  public <P extends Parameters> ProtoBasedConfigurationBuilder addKeyCreator(
      Class<P> parametersClass, KeyCreator<P> creator) {
    if (keyCreators.containsKey(parametersClass)) {
      throw new IllegalArgumentException("KeyCreator for " + parametersClass + " already added.");
    }
    keyCreators.put(parametersClass, creator);
    return this;
  }

  public Configuration build() {
    return new InternalProtoBasedConfiguration(keyCreators);
  }
}
