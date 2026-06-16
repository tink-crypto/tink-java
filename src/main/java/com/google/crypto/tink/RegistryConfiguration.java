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

package com.google.crypto.tink;

import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * RegistryConfiguration is a proxy Configuration that forwards all calls to the global Registry.
 */
public class RegistryConfiguration {
  // Returns the singleton instance of RegistryConfiguration.
  public static Configuration get() throws GeneralSecurityException {
    return CONFIG;
  }

  private static class RegistryProtoKeySerializer implements ProtoKeySerializer {
    @Override
    public Key parseKey(
        com.google.crypto.tink.ProtoKeySerialization protoKeySerialization,
        @Nullable SecretKeyAccess access)
        throws GeneralSecurityException {
      return MutableSerializationRegistry.globalInstance()
          .parseKeyWithLegacyFallback(protoKeySerialization, access);
    }

    @Override
    public com.google.crypto.tink.ProtoKeySerialization serializeKey(
        Key key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
      return MutableSerializationRegistry.globalInstance().serializeKey(key, access);
    }

    @Override
    public ProtoParametersSerialization serializeParameters(Parameters parameters)
        throws GeneralSecurityException {
      return MutableSerializationRegistry.globalInstance().serializeParameters(parameters);
    }

    @Override
    @SuppressWarnings("UnnecessarilyFullyQualified") // We fully specify proto KeyTemplate in Tink.
    public Parameters parseParameters(ProtoParametersSerialization serialization)
        throws GeneralSecurityException {
      return MutableSerializationRegistry.globalInstance()
          .parseParametersWithLegacyFallback(serialization);
    }
  }

  private static final RegistryProtoKeySerializer SERIALIZER = new RegistryProtoKeySerializer();
  private static final Configuration CONFIG =
      new Configuration() {
        @Override
        public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
            throws GeneralSecurityException {
          return MutablePrimitiveRegistry.globalInstance().wrap(keysetHandle, clazz);
        }

        @Override
        public <P> P getOrNull(Class<P> clazz) {
          if (clazz.equals(ProtoKeySerializer.class)) {
            return clazz.cast(SERIALIZER);
          }
          return null;
        }
      };

  private RegistryConfiguration() {}
}
