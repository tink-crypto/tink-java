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

import com.google.crypto.tink.Parameters;
import java.security.GeneralSecurityException;

/**
 * Parses {@code Serialization} objects into {@code Parameters} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class ParametersParser {
  /**
   * A function which parses a Parameters object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface ParametersParsingFunction {
    Parameters parseParameters(ProtoParametersSerialization serialization)
        throws GeneralSecurityException;
  }

  private final String typeUrl;

  private ParametersParser(String typeUrl) {
    this.typeUrl = typeUrl;
  }

  /**
   * Parses a serialization into a {@link Parameters} object.
   *
   * <p>This function is usually called with a Serialization matching the result of {@link
   * getObjectIdentifier}. However, implementations should check that this is the case.
   */
  public abstract Parameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException;

  /** Returns the {@code getTypeUrl} for this serialization. */
  public final String getTypeUrl() {
    return typeUrl;
  }

  public final Class<ProtoParametersSerialization> getSerializationClass() {
    return ProtoParametersSerialization.class;
  }

  /**
   * Creates a ParametersParser object.
   *
   * <p>In order to create a ParametersParser object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MyParameters parse(ProtoParametersSerialization parametersSerialization)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code ParametersParser}:
   *
   * <pre>{@code
   * ParametersParser parser =
   *       ParametersParser.create(MyClass::parse, objectIdentifier);
   * }</pre>
   *
   * @param function The function used to parse a {@link Parameters} object.
   * @param objectIdentifier The identifier to be returned by {@link #getObjectIdentifier}
   */
  public static ParametersParser create(ParametersParsingFunction function, String typeUrl) {
    return new ParametersParser(typeUrl) {
      @Override
      public Parameters parseParameters(ProtoParametersSerialization serialization)
          throws GeneralSecurityException {
        return function.parseParameters(serialization);
      }
    };
  }

}
