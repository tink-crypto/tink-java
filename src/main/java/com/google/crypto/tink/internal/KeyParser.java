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
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.SecretKeyAccess;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Parses {@code Serialization} objects into {@code Key} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeyParser {
  /**
   * A function which parses a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeyParsingFunction {
    Key parseKey(ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
        throws GeneralSecurityException;
  }

  private final String typeUrl;

  private KeyParser(String typeUrl) {
    this.typeUrl = typeUrl;
  }

  /**
   * Parses a serialization into a key.
   *
   * <p>This function is usually called with a Serialization matching the result of {@link
   * getObjectIdentifier}. However, implementations should check that this is the case.
   */
  public abstract Key parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException;

  /**
   * Returns the {@code objectIdentifier} for this serialization.
   *
   * <p>The object identifier is a unique identifier per registry for this object (in the standard
   * proto serialization, it is the typeUrl). In other words, when registering a {@code KeyParser},
   * the registry will invoke this to get the handled object identifier. In order to parse an object
   * of type {@code ProtoKeySerialization}, the registry will then obtain the {@code
   * objectIdentifier} of this serialization object, and call the parser corresponding to this
   * object.
   */
  public final String getTypeUrl() {
    return typeUrl;
  }

  public final Class<ProtoKeySerialization> getSerializationClass() {
    return ProtoKeySerialization.class;
  }

  /**
   * Creates a KeyParser object.
   *
   * <p>In order to create a KeyParser object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MyKey parse(ProtoKeySerialization s, @Nullable SecretKeyAccess access)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyParser}:
   *
   * <pre>{@code
   * KeyParser parser =
   *       KeyParser.create(MyClass::parse, objectIdentifier);
   * }</pre>
   *
   * Note that calling this function twice will result in objects which are not equal according to
   * {@code Object.equals}, and hence cannot be used to re-register a previously registered object.
   *
   * @param function The function used to parse a Key
   * @param objectIdentifier The identifier to be returned by {@link #getObjectIdentifier}
   */
  public static KeyParser create(KeyParsingFunction function, String typeUrl) {
    return new KeyParser(typeUrl) {
      @Override
      public Key parseKey(ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
          throws GeneralSecurityException {
        return function.parseKey(serialization, access);
      }
    };
  }
}
