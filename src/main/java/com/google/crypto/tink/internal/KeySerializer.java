// Copyright 2022 Google LLC
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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.SecretKeyAccess;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Serializes {@code Key} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeySerializer<KeyT extends Key> {
  /**
   * A function which serializes a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeySerializationFunction<KeyT extends Key> {
    ProtoKeySerialization serializeKey(KeyT key, @Nullable SecretKeyAccess access)
        throws GeneralSecurityException;
  }

  private final Class<KeyT> keyClass;

  private KeySerializer(Class<KeyT> keyClass) {
    this.keyClass = keyClass;
  }

  public abstract ProtoKeySerialization serializeKey(KeyT key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException;

  public Class<KeyT> getKeyClass() {
    return keyClass;
  }

  public Class<ProtoKeySerialization> getSerializationClass() {
    return ProtoKeySerialization.class;
  }

  /**
   * Creates a KeySerializer object.
   *
   * <p>In order to create a KeySerializer object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static ProtoKeySerialization serialize(MyKey key, @Nullable SecretKeyAccess access)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeySerializer}:
   *
   * <pre>{@code
   * KeySerializer<MyKey> serializer =
   *     KeySerializer.create(MyClass::serialize, MyKey.class);
   * }</pre>
   *
   * <p>Note that calling this function twice will result in objects which are not equal according
   * to {@code Object.equals}, and hence cannot be used to re-register a previously registered
   * object.
   */
  public static <KeyT extends Key> KeySerializer<KeyT> create(
      KeySerializationFunction<KeyT> function, Class<KeyT> keyClass) {
    return new KeySerializer<KeyT>(keyClass) {
      @Override
      public ProtoKeySerialization serializeKey(KeyT key, @Nullable SecretKeyAccess access)
          throws GeneralSecurityException {
        return function.serializeKey(key, access);
      }
    };
  }
}
