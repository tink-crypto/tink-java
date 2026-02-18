// Copyright 2023 Google LLC
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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InternalConfiguration}. */
@RunWith(JUnit4.class)
public class InternalConfigurationTest {

  private static KeysetHandle arbitraryKeyset;

  @BeforeClass
  public static void setUpKeyset() throws Exception {
    AeadConfig.register();
    arbitraryKeyset = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
  }

  @Immutable
  private static final class TestPrimitiveA {
    public TestPrimitiveA() {}
  }

  @Immutable
  private static final class TestPrimitiveB {
    public TestPrimitiveB() {}
  }

  @Immutable
  private static final class TestWrapperA
      implements PrimitiveWrapper<TestPrimitiveA, TestPrimitiveA> {

    @Override
    public TestPrimitiveA wrap(
        KeysetHandleInterface keysetHandle, PrimitiveFactory<TestPrimitiveA> factory) {
      return new TestPrimitiveA();
    }

    @Override
    public Class<TestPrimitiveA> getPrimitiveClass() {
      return TestPrimitiveA.class;
    }

    @Override
    public Class<TestPrimitiveA> getInputPrimitiveClass() {
      return TestPrimitiveA.class;
    }
  }

  @Immutable
  private static final class TestWrapperB
      implements PrimitiveWrapper<TestPrimitiveB, TestPrimitiveB> {

    @Override
    public TestPrimitiveB wrap(
        KeysetHandleInterface keysetHandle, PrimitiveFactory<TestPrimitiveB> factory) {
      return new TestPrimitiveB();
    }

    @Override
    public Class<TestPrimitiveB> getPrimitiveClass() {
      return TestPrimitiveB.class;
    }

    @Override
    public Class<TestPrimitiveB> getInputPrimitiveClass() {
      return TestPrimitiveB.class;
    }
  }

  @Test
  public void wrap_works() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    // Check that the type is as expected.
    TestPrimitiveA unused = configuration.wrap(arbitraryKeyset, TestPrimitiveA.class);
  }

  @Test
  public void wrap_dispatchWorks() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveWrapper(new TestWrapperA())
            .registerPrimitiveWrapper(new TestWrapperB())
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    // Check that the wrapped primitives are of the expected types.
    TestPrimitiveA unusedA = configuration.wrap(arbitraryKeyset, TestPrimitiveA.class);
    TestPrimitiveB unusedB = configuration.wrap(arbitraryKeyset, TestPrimitiveB.class);
  }

  @Test
  public void wrap_unregisteredWrapperClassThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.wrap(arbitraryKeyset, TestPrimitiveB.class));
  }


  @Test
  public void emptyRegistry_throws() {
    PrimitiveRegistry registry = PrimitiveRegistry.builder().build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.wrap(arbitraryKeyset, TestPrimitiveA.class));
  }
}
