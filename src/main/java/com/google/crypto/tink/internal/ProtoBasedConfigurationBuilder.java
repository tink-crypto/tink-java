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
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Parameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * ProtoBasedConfigurationBuilder helps create {@link Configuration} instances.
 *
 * <p>It is especially optimized to create standard configurations where serialization and parsing
 * is based on the Protobuf serialization which Tink uses.
 */
public final class ProtoBasedConfigurationBuilder {

  /** Functional interface to wrap a keyset into a primitive. */
  @FunctionalInterface
  public interface WrapFunction<B, P> {
    P wrap(KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<B> factory)
        throws GeneralSecurityException;
  }

  /**
   * A pair (Class<? extends Key>, Class<?>) used to index into a map for primitive constructors.
   */
  private static final class PrimitiveConstructorKey {
    private final Class<? extends Key> keyClass;
    private final Class<?> primitiveClass;

    private PrimitiveConstructorKey(Class<? extends Key> keyClass, Class<?> primitiveClass) {
      this.keyClass = keyClass;
      this.primitiveClass = primitiveClass;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof PrimitiveConstructorKey)) {
        return false;
      }
      PrimitiveConstructorKey other = (PrimitiveConstructorKey) o;
      return other.keyClass.equals(keyClass) && other.primitiveClass.equals(primitiveClass);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keyClass, primitiveClass);
    }

    @Override
    public String toString() {
      return keyClass.getSimpleName() + " with primitive type: " + primitiveClass.getSimpleName();
    }
  }

  private static final class InternalProtoBasedConfiguration implements Configuration {
    private final Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators;
    private final Map<PrimitiveConstructorKey, PrimitiveConstructor<?, ?>> primitiveConstructors;
    private final Map<Class<?>, WrapFunctionAndInputPrimitiveClass<?, ?>> wrappers;

    InternalProtoBasedConfiguration(
        Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators,
        Map<PrimitiveConstructorKey, PrimitiveConstructor<?, ?>> primitiveConstructors,
        Map<Class<?>, WrapFunctionAndInputPrimitiveClass<?, ?>> wrappers) {
      this.keyCreators = Collections.unmodifiableMap(new HashMap<>(keyCreators));
      this.primitiveConstructors =
          Collections.unmodifiableMap(new HashMap<>(primitiveConstructors));
      this.wrappers = Collections.unmodifiableMap(new HashMap<>(wrappers));
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

    @Override
    public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
        throws GeneralSecurityException {
      WrapFunctionAndInputPrimitiveClass<?, ?> wrapFunctionAndInputPrimitiveClass =
          wrappers.get(clazz);
      if (wrapFunctionAndInputPrimitiveClass == null) {
        throw new GeneralSecurityException(
            "No wrapper registered for primitive class: " + clazz.getName());
      }
      @SuppressWarnings("unchecked") // We create the map so that it satisfies this.
      WrapFunctionAndInputPrimitiveClass<?, P> typedRegistration =
          (WrapFunctionAndInputPrimitiveClass<?, P>) wrapFunctionAndInputPrimitiveClass;
      return wrapHelper(typedRegistration, keysetHandle);
    }

    private <B, P> P wrapHelper(
        WrapFunctionAndInputPrimitiveClass<B, P> registration, KeysetHandleInterface keysetHandle)
        throws GeneralSecurityException {
      return registration.wrapFunction.wrap(
          keysetHandle, entry -> createInputPrimitive(entry, registration.inputPrimitiveClass));
    }

    private <B> B createInputPrimitive(
        KeysetHandleInterface.Entry entry, Class<B> inputPrimitiveClass)
        throws GeneralSecurityException {
      Key key = entry.getKey();
      PrimitiveConstructorKey keyPair =
          new PrimitiveConstructorKey((Class<? extends Key>) key.getClass(), inputPrimitiveClass);
      @SuppressWarnings("unchecked") // We create the map so that it satisfies this.
      PrimitiveConstructor<Key, B> constructor =
          (PrimitiveConstructor<Key, B>) primitiveConstructors.get(keyPair);
      if (constructor == null) {
        throw new GeneralSecurityException(
            "No PrimitiveConstructor registered for key class "
                + key.getClass().getName()
                + " and primitive "
                + inputPrimitiveClass.getName());
      }
      return constructor.constructPrimitive(key);
    }
  }

  /**
   * A pair (inputPrimitiveClass, wrapFunction). The wrap function knows how to create primitives of
   * type P given a primitive creator for type B.
   */
  private static final class WrapFunctionAndInputPrimitiveClass<B, P> {
    private final Class<B> inputPrimitiveClass;
    private final WrapFunction<B, P> wrapFunction;

    private WrapFunctionAndInputPrimitiveClass(
        Class<B> inputPrimitiveClass, WrapFunction<B, P> wrapFunction) {
      this.inputPrimitiveClass = inputPrimitiveClass;
      this.wrapFunction = wrapFunction;
    }
  }

  private final Map<Class<? extends Parameters>, KeyCreator<?>> keyCreators = new HashMap<>();
  private final Map<PrimitiveConstructorKey, PrimitiveConstructor<?, ?>> primitiveConstructors =
      new HashMap<>();
  private final Map<Class<?>, WrapFunctionAndInputPrimitiveClass<?, ?>> wrappers = new HashMap<>();

  public ProtoBasedConfigurationBuilder() {}

  /** Add a method to create keys from the given parameters. */
  @CanIgnoreReturnValue
  public <P extends Parameters> ProtoBasedConfigurationBuilder addKeyCreator(
      Class<P> parametersClass, KeyCreator<P> creator) {
    if (keyCreators.containsKey(parametersClass)) {
      throw new IllegalArgumentException("KeyCreator for " + parametersClass + " already added.");
    }
    keyCreators.put(parametersClass, creator);
    return this;
  }

  /** Add a method to create (single key) primitives from a given key. */
  @CanIgnoreReturnValue
  public <KeyT extends Key, PrimitiveT> ProtoBasedConfigurationBuilder addPrimitiveConstructor(
      PrimitiveConstructor.PrimitiveConstructionFunction<KeyT, PrimitiveT> constructionFunction,
      Class<KeyT> keyClass,
      Class<PrimitiveT> primitiveClass) {
    PrimitiveConstructorKey key = new PrimitiveConstructorKey(keyClass, primitiveClass);
    if (primitiveConstructors.containsKey(key)) {
      throw new IllegalArgumentException(
          "PrimitiveConstructor for "
              + keyClass
              + " and primitive "
              + primitiveClass
              + " already added.");
    }
    primitiveConstructors.put(
        key, PrimitiveConstructor.create(constructionFunction, keyClass, primitiveClass));
    return this;
  }

  /** Add a method to create a primitive from a keyset. */
  @CanIgnoreReturnValue
  public <InputPrimitiveT, WrapperPrimitiveT> ProtoBasedConfigurationBuilder addPrimitiveWrapper(
      Class<WrapperPrimitiveT> primitiveClass,
      Class<InputPrimitiveT> inputPrimitiveClass,
      WrapFunction<InputPrimitiveT, WrapperPrimitiveT> wrapFunction) {
    if (wrappers.containsKey(primitiveClass)) {
      throw new IllegalArgumentException(
          "PrimitiveWrapper for " + primitiveClass + " already added.");
    }
    wrappers.put(
        primitiveClass,
        new WrapFunctionAndInputPrimitiveClass<>(inputPrimitiveClass, wrapFunction));
    return this;
  }

  public Configuration build() {
    return new InternalProtoBasedConfiguration(keyCreators, primitiveConstructors, wrappers);
  }
}
