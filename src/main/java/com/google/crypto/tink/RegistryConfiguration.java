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
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
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
          .parseKey(
              com.google.crypto.tink.internal.ProtoKeySerialization.createFromPublic(
                  protoKeySerialization),
              access);
    }

    @Override
    public com.google.crypto.tink.ProtoKeySerialization serializeKey(
        Key key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
      return MutableSerializationRegistry.globalInstance()
          .serializeKey(key, com.google.crypto.tink.internal.ProtoKeySerialization.class, access)
          .toPublic();
    }

    @Override
    public ByteString serializeParameters(Parameters parameters) throws GeneralSecurityException {
      ProtoParametersSerialization serialization =
          MutableSerializationRegistry.globalInstance()
              .serializeParameters(parameters, ProtoParametersSerialization.class);
      return serialization.getKeyTemplate().toByteString();
    }

    @Override
    @SuppressWarnings("UnnecessarilyFullyQualified") // We fully specify KeyTemplate in Tink.
    public Parameters parseParameters(ByteString serialization) throws GeneralSecurityException {
      try {
        com.google.crypto.tink.proto.KeyTemplate template =
            com.google.crypto.tink.proto.KeyTemplate.parseFrom(
                serialization, ExtensionRegistryLite.getEmptyRegistry());
        return MutableSerializationRegistry.globalInstance()
            .parseParameters(ProtoParametersSerialization.create(template));
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException("Problem parsing the parameters", e);
      }
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
        public <P> P get(Class<P> clazz) throws GeneralSecurityException {
          if (clazz.equals(ProtoKeySerializer.class)) {
            return clazz.cast(SERIALIZER);
          }
          throw new GeneralSecurityException(
              "RegistryConfiguration does not support get for " + clazz);
        }
      };

  private RegistryConfiguration() {}
}
