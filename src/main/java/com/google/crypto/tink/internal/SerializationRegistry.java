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
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Allows registering {@code KeySerializer}, {@code KeyParser}, {@code ParametersSerializer}, and
 * {@link ParametersParser} objects, and parsing/serializing keys and key formats with such objects.
 */
public final class SerializationRegistry {
  // Maps the class of a key to a serializer for this key.
  private final Map<Class<?>, KeySerializer<?>> keySerializerMap;
  private final Map<Bytes, KeyParser> keyParserMap;
  // Maps the class of a parameters to a serializer for these parameters.
  private final Map<Class<?>, ParametersSerializer<?, ProtoParametersSerialization>>
      parametersSerializerMap;
  private final Map<Bytes, ParametersParser> parametersParserMap;

  /** Allows building SerializationRegistry objects. */
  public static final class Builder {
    private final Map<Class<?>, KeySerializer<?>> keySerializerMap;
    private final Map<Bytes, KeyParser> keyParserMap;
    private final Map<Class<?>, ParametersSerializer<?, ProtoParametersSerialization>>
        parametersSerializerMap;
    private final Map<Bytes, ParametersParser> parametersParserMap;

    public Builder() {
      keySerializerMap = new HashMap<>();
      keyParserMap = new HashMap<>();
      parametersSerializerMap = new HashMap<>();
      parametersParserMap = new HashMap<>();
    }

    public Builder(SerializationRegistry registry) {
      keySerializerMap = new HashMap<>(registry.keySerializerMap);
      keyParserMap = new HashMap<>(registry.keyParserMap);
      parametersSerializerMap = new HashMap<>(registry.parametersSerializerMap);
      parametersParserMap = new HashMap<>(registry.parametersParserMap);
    }

    /**
     * Registers a key serializer for later use in {@link #serializeKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has
     * already been registered, this checks if they are the same. If they are, the call is ignored,
     * otherwise an exception is thrown.
     */
    @CanIgnoreReturnValue
    public <KeyT extends Key> Builder registerKeySerializer(KeySerializer<KeyT> serializer)
        throws GeneralSecurityException {
      if (keySerializerMap.containsKey(serializer.getKeyClass())) {
        KeySerializer<?> existingSerializer = keySerializerMap.get(serializer.getKeyClass());
        if (!existingSerializer.equals(serializer) || !serializer.equals(existingSerializer)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal serializer for already existing object of type: "
                  + serializer.getKeyClass());
        }
      } else {
        keySerializerMap.put(serializer.getKeyClass(), serializer);
      }
      return this;
    }

    /**
     * Registers a key parser for later use in {@link #parseKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #parseKey}. If a parser for the pair {@code (SerializationT,
     * parser.getObjectIdentifier())} has already been registered, this checks if they are the same.
     * If they are, the call is ignored, otherwise an exception is thrown.
     */
    @CanIgnoreReturnValue
    public Builder registerKeyParser(KeyParser parser) throws GeneralSecurityException {
      Bytes index = parser.getObjectIdentifier();
      if (keyParserMap.containsKey(index)) {
        KeyParser existingParser = keyParserMap.get(index);
        if (!existingParser.equals(parser) || !parser.equals(existingParser)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal parser for already existing object of type: " + index);
        }
      } else {
        keyParserMap.put(index, parser);
      }
      return this;
    }

    /**
     * Registers a key serializer for later use in {@link #serializeKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has
     * already been registered, this checks if they are the same. If they are, the call is ignored,
     * otherwise an exception is thrown.
     */
    @CanIgnoreReturnValue
    public <ParametersT extends Parameters> Builder registerParametersSerializer(
        ParametersSerializer<ParametersT, ProtoParametersSerialization> serializer)
        throws GeneralSecurityException {
      if (parametersSerializerMap.containsKey(serializer.getParametersClass())) {
        ParametersSerializer<?, ProtoParametersSerialization> existingSerializer =
            parametersSerializerMap.get(serializer.getParametersClass());
        if (!existingSerializer.equals(serializer) || !serializer.equals(existingSerializer)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal serializer for already existing object of type: "
                  + serializer.getParametersClass());
        }
      } else {
        parametersSerializerMap.put(serializer.getParametersClass(), serializer);
      }
      return this;
    }

    /**
     * Registers a key parser for later use in {@link #parseKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #parseKey}. If a parser for the pair {@code (SerializationT,
     * parser.getObjectIdentifier())} has already been registered, this checks if they are the same.
     * If they are, the call is ignored, otherwise an exception is thrown.
     */
    @CanIgnoreReturnValue
    public Builder registerParametersParser(ParametersParser parser)
        throws GeneralSecurityException {
      Bytes index = parser.getObjectIdentifier();
      if (parametersParserMap.containsKey(index)) {
        ParametersParser existingParser = parametersParserMap.get(index);
        if (!existingParser.equals(parser) || !parser.equals(existingParser)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal parser for already existing object of type: " + index);
        }
      } else {
        parametersParserMap.put(index, parser);
      }
      return this;
    }

    public SerializationRegistry build() {
      return new SerializationRegistry(this);
    }
  }

  private SerializationRegistry(Builder builder) {
    keySerializerMap = new HashMap<>(builder.keySerializerMap);
    keyParserMap = new HashMap<>(builder.keyParserMap);
    parametersSerializerMap = new HashMap<>(builder.parametersSerializerMap);
    parametersParserMap = new HashMap<>(builder.parametersParserMap);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public boolean hasParserForKey(ProtoKeySerialization serializedKey) {
    return keyParserMap.containsKey(serializedKey.getObjectIdentifier());
  }

  /**
   * Parses the given serialization into a Key.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public Key parseKey(ProtoKeySerialization serializedKey, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    Bytes index = serializedKey.getObjectIdentifier();

    if (!keyParserMap.containsKey(index)) {
      throw new GeneralSecurityException(
          "No Key Parser for requested key type " + index + " available");
    }
    // We know we only insert like this.
    KeyParser parser = keyParserMap.get(index);
    return parser.parseKey(serializedKey, access);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <KeyT extends Key> boolean hasSerializerForKey(KeyT key, Class<?> serializationClass) {
    return keySerializerMap.containsKey(key.getClass())
        && serializationClass.equals(ProtoKeySerialization.class);
  }

  /**
   * Serializes a given Key into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <KeyT extends Key> ProtoKeySerialization serializeKey(
      KeyT key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    if (!keySerializerMap.containsKey(key.getClass())) {
      throw new GeneralSecurityException("No Key serializer for " + key.getClass() + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeySerializer<KeyT> serializer = (KeySerializer<KeyT>) keySerializerMap.get(key.getClass());
    return serializer.serializeKey(key, access);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public boolean hasParserForParameters(ProtoParametersSerialization serializedParameters) {
    return parametersParserMap.containsKey(serializedParameters.getObjectIdentifier());
  }

  /**
   * Parses the given serialization into a Parameters.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public Parameters parseParameters(ProtoParametersSerialization serializedParameters)
      throws GeneralSecurityException {
    Bytes index = serializedParameters.getObjectIdentifier();

    if (!parametersParserMap.containsKey(index)) {
      throw new GeneralSecurityException(
          "No Parameters Parser for requested key type " + index + " available");
    }
    // We know we only insert like this.
    ParametersParser parser = parametersParserMap.get(index);
    return parser.parseParameters(serializedParameters);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <ParametersT extends Parameters> boolean hasSerializerForParameters(
      ParametersT parameters, Class<?> serializationClass) {
    return parametersSerializerMap.containsKey(parameters.getClass())
        && serializationClass.equals(ProtoParametersSerialization.class);
  }

  /**
   * Serializes a given Parameters object into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <ParametersT extends Parameters> ProtoParametersSerialization serializeParameters(
      ParametersT parameters) throws GeneralSecurityException {
    if (!parametersSerializerMap.containsKey(parameters.getClass())) {
      throw new GeneralSecurityException(
          "No Key Format serializer for " + parameters.getClass() + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    ParametersSerializer<ParametersT, ProtoParametersSerialization> serializer =
        (ParametersSerializer<ParametersT, ProtoParametersSerialization>)
            parametersSerializerMap.get(parameters.getClass());
    return serializer.serializeParameters(parameters);
  }
}
