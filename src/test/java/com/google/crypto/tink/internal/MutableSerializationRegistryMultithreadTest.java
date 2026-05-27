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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Thread safety tests for {@link MutableSerializationRegistry}. */
@RunWith(JUnit4.class)
public final class MutableSerializationRegistryMultithreadTest {
  private static final SecretKeyAccess ACCESS = InsecureSecretKeyAccess.get();

  private static final String TYPE_URL_1 = "type_url_1";
  private static final String TYPE_URL_2 = "type_url_2";

  private static final Bytes A_1 = Bytes.copyFrom(TYPE_URL_1.getBytes(UTF_8));

  @Immutable
  private static final class TestParameters1 extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static final class TestParameters2 extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static final class TestKey1 extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Immutable
  private static final class TestKey2 extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  private static ProtoKeySerialization serializeKey1ToProto(
      TestKey1 key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return ProtoKeySerialization.create(
        TYPE_URL_1,
        ByteString.EMPTY,
        KeyMaterialType.SYMMETRIC,
        OutputPrefixType.RAW,
        /* idRequirement= */ null);
  }

  private static ProtoKeySerialization serializeKey2ToProto(
      TestKey2 key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return ProtoKeySerialization.create(
        TYPE_URL_2,
        ByteString.EMPTY,
        KeyMaterialType.SYMMETRIC,
        OutputPrefixType.RAW,
        /* idRequirement= */ null);
  }

  private static Key parseProtoToKey1(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!TYPE_URL_1.equals(serialization.getTypeUrl())) {
      throw new GeneralSecurityException("Wrong type URL");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey1();
  }

  private static ProtoParametersSerialization serializeParameters1ToProto(
      TestParameters1 parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
  }

  private static ProtoParametersSerialization serializeParameters2ToProto(
      TestParameters2 parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(TYPE_URL_2, OutputPrefixType.RAW, ByteString.EMPTY);
  }

  private static Parameters parseProtoToParameters1(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!TYPE_URL_1.equals(serialization.getTypeUrl())) {
      throw new GeneralSecurityException("Wrong type URL");
    }
    return new TestParameters1();
  }

  private static final int REPETITIONS = 1000;

  @Test
  public void registerAndParseAndSerializeInParallel_works() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ExecutorService threadPool = Executors.newFixedThreadPool(4);
    List<Future<?>> futures = new ArrayList<>();
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryMultithreadTest::serializeKey1ToProto, TestKey1.class));
    registry.registerKeyParser(
        KeyParser.create(MutableSerializationRegistryMultithreadTest::parseProtoToKey1, A_1));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryMultithreadTest::serializeParameters1ToProto,
            TestParameters1.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryMultithreadTest::parseProtoToParameters1, A_1));

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            TYPE_URL_1,
            OutputPrefixType.RAW,
            ByteString.EMPTY);

    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.registerKeyParser(
                      KeyParser.create(
                          MutableSerializationRegistryMultithreadTest::parseProtoToKey1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array())));
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                // This thread mainly wants to do a key serializer registration, but we only have
                // one of those, since each needs either a new serialization class, or a new key
                // class. So first do a few parsing registrations to mix things up.
                for (int i = 0; i < REPETITIONS / 2; ++i) {
                  registry.registerKeyParser(
                      KeyParser.create(
                          MutableSerializationRegistryMultithreadTest::parseProtoToKey1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i + REPETITIONS).array())));
                }
                registry.registerKeySerializer(
                    KeySerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeKey2ToProto,
                        TestKey2.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  Object unused = registry.parseKey(serialization, ACCESS);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  Object unused = registry.serializeKey(new TestKey1(), ACCESS);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    // =============================== More threads doing the same thing, this time for parameters.
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.registerParametersParser(
                      ParametersParser.create(
                          MutableSerializationRegistryMultithreadTest::parseProtoToParameters1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array())));
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                // This thread mainly wants to do a key serializer registration, but we only have
                // one of those, since each needs either a new serialization class, or a new key
                // class. So first do a few parsing registrations to mix things up.
                for (int i = 0; i < REPETITIONS / 2; ++i) {
                  registry.registerParametersParser(
                      ParametersParser.create(
                          MutableSerializationRegistryMultithreadTest::parseProtoToParameters1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i + REPETITIONS).array())));
                }
                registry.registerParametersSerializer(
                    ParametersSerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeParameters2ToProto,
                        TestParameters2.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));

    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  Object unused = registry.parseParameters(protoParameters);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  Object unused = registry.serializeParameters(new TestParameters1());
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));

    threadPool.shutdown();
    assertThat(threadPool.awaitTermination(300, SECONDS)).isTrue();
    for (int i = 0; i < futures.size(); ++i) {
      futures.get(i).get(); // This will throw an exception if the thread threw an exception.
    }
  }
}
