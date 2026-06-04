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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link SerializationRegistry}. */
@RunWith(JUnit4.class)
public final class SerializationRegistryTest {

  private static final SecretKeyAccess ACCESS = InsecureSecretKeyAccess.get();

  private static final String TYPE_URL_1 = "type_url_1";
  private static final String TYPE_URL_2 = "type_url_2";

  private static final Bytes A_1 = Bytes.copyFrom(TYPE_URL_1.getBytes(UTF_8));
  private static final Bytes A_2 = Bytes.copyFrom(TYPE_URL_2.getBytes(UTF_8));

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

  private static Key parseProtoToKey2(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!TYPE_URL_2.equals(serialization.getTypeUrl())) {
      throw new GeneralSecurityException("Wrong type URL");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey2();
  }

  // ======================================================================= Key serialization tests
  @Test
  public void test_registerSerializerAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToProto, TestKey1.class))
            .build();
    assertThat(registry.hasSerializerForKey(new TestKey1(), ProtoKeySerialization.class)).isTrue();
    assertThat(registry.serializeKey(new TestKey1(), ACCESS)).isNotNull();
  }

  @Test
  public void test_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThat(registry.hasSerializerForKey(new TestKey1(), ProtoKeySerialization.class)).isFalse();
    assertThrows(
        GeneralSecurityException.class, () -> registry.serializeKey(new TestKey1(), ACCESS));
  }

  @Test
  public void test_noAccessSerializer_throws() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToProto, TestKey1.class))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(new TestKey1(), /* access= */ null));
  }

  @Test
  public void test_registerSameSerializerTwice_works() throws Exception {
    KeySerializer<TestKey1> testSerializer =
        KeySerializer.create(SerializationRegistryTest::serializeKey1ToProto, TestKey1.class);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerKeySerializer(testSerializer)
        .registerKeySerializer(testSerializer)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithSameKeyType_throws() throws Exception {
    KeySerializer<TestKey1> testSerializer1 =
        KeySerializer.create(SerializationRegistryTest::serializeKey1ToProto, TestKey1.class);
    KeySerializer<TestKey1> testSerializer2 =
        KeySerializer.create(SerializationRegistryTest::serializeKey1ToProto, TestKey1.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerKeySerializer(testSerializer1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerKeySerializer(testSerializer2));
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentKeyType_works() throws Exception {
    KeySerializer<TestKey1> testSerializer1 =
        KeySerializer.create(SerializationRegistryTest::serializeKey1ToProto, TestKey1.class);
    KeySerializer<TestKey2> testSerializer2 =
        KeySerializer.create(SerializationRegistryTest::serializeKey2ToProto, TestKey2.class);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerKeySerializer(testSerializer1)
        .registerKeySerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerAll_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToProto, TestKey1.class))
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey2ToProto, TestKey2.class))
            .build();
    assertThat(registry.serializeKey(new TestKey1(), ACCESS).getTypeUrl()).isEqualTo(TYPE_URL_1);
    assertThat(registry.serializeKey(new TestKey2(), ACCESS).getTypeUrl()).isEqualTo(TYPE_URL_2);
  }

  @Test
  public void test_serializer_copyWorks() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToProto, TestKey1.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.serializeKey(new TestKey1(), ACCESS)).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_serializer() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();
    builder.registerKeySerializer(
        KeySerializer.create(SerializationRegistryTest::serializeKey1ToProto, TestKey1.class));
    assertThrows(
        GeneralSecurityException.class, () -> registry1.serializeKey(new TestKey1(), ACCESS));
    assertThrows(
        GeneralSecurityException.class, () -> registry2.serializeKey(new TestKey1(), ACCESS));
  }

  // ============================================================================= Key parsing tests
  @Test
  public void test_registerParserAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThat(registry.hasParserForKey(serialization)).isTrue();
    assertThat(registry.parseKey(serialization, ACCESS)).isNotNull();
  }

  @Test
  public void test_registerParser_noAccess_throws() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void test_parse_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThat(registry.hasParserForKey(serialization)).isFalse();
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, ACCESS));
  }

  @Test
  public void test_registerSameParserTwice_works() throws Exception {
    KeyParser testParser = KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerKeyParser(testParser)
        .registerKeyParser(testParser)
        .build();
  }

  @Test
  public void test_registerDifferentParsersWithSameKeyType_throws() throws Exception {
    KeyParser testParser1 = KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1);
    KeyParser testParser2 = KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerKeyParser(testParser1);
    assertThrows(
        GeneralSecurityException.class, () -> builder.registerKeyParser(testParser2));
  }

  @Test
  public void test_registerDifferentParsersWithDifferentKeyType_works() throws Exception {
    KeyParser testParser1 = KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1);
    KeyParser testParser2 = KeyParser.create(SerializationRegistryTest::parseProtoToKey2, A_2);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerKeyParser(testParser1)
        .registerKeyParser(testParser2)
        .build();
  }

  @Test
  public void test_registerAllParsers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1))
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey2, A_2))
            .build();
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            TYPE_URL_2,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThat(registry.parseKey(serialization1, ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(serialization2, ACCESS)).isInstanceOf(TestKey2.class);
  }

  @Test
  public void test_copyWorksForParsers() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThat(registry2.parseKey(serialization, ACCESS)).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_parser() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL_1,
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    SerializationRegistry unused =
        builder
            .registerKeyParser(KeyParser.create(SerializationRegistryTest::parseProtoToKey1, A_1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> registry1.parseKey(serialization, ACCESS));
    assertThrows(GeneralSecurityException.class, () -> registry2.parseKey(serialization, ACCESS));
  }

  // ================================================================================================
  // PARAMETERS TESTS
  // ================================================================================================
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

  private static Parameters parseProtoToParameters2(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!TYPE_URL_2.equals(serialization.getTypeUrl())) {
      throw new GeneralSecurityException("Wrong type URL");
    }
    return new TestParameters2();
  }

  // ParametersSerialization tests
  @Test
  public void test_registerParametersSerializerAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class))
            .build();
    assertThat(
            registry.hasSerializerForParameters(
                new TestParameters1(), ProtoParametersSerialization.class))
        .isTrue();
    assertThat(registry.serializeParameters(new TestParameters1())).isNotNull();
  }

  @Test
  public void test_emptyRegistrySerializeParameters_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThat(
            registry.hasSerializerForParameters(
                new TestParameters1(), ProtoParametersSerialization.class))
        .isFalse();
    assertThrows(
        GeneralSecurityException.class, () -> registry.serializeParameters(new TestParameters1()));
  }

  @Test
  public void test_registerSameParametersSerializerTwice_works() throws Exception {
    ParametersSerializer<TestParameters1> testSerializer =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerParametersSerializer(testSerializer)
        .registerParametersSerializer(testSerializer)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithSameParametersType_throws() throws Exception {
    ParametersSerializer<TestParameters1> testSerializer1 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class);
    ParametersSerializer<TestParameters1> testSerializer2 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerParametersSerializer(testSerializer1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerParametersSerializer(testSerializer2));
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentParametersType_works() throws Exception {
    ParametersSerializer<TestParameters1> testSerializer1 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class);
    ParametersSerializer<TestParameters2> testSerializer2 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters2ToProto, TestParameters2.class);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerParametersSerializer(testSerializer1)
        .registerParametersSerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerAllParametersSerializers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class))
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters2ToProto, TestParameters2.class))
            .build();
    assertThat(registry.serializeParameters(new TestParameters1()).getTypeUrl())
        .isEqualTo(TYPE_URL_1);
    assertThat(registry.serializeParameters(new TestParameters2()).getTypeUrl())
        .isEqualTo(TYPE_URL_2);
  }

  @Test
  public void test_formatSerializer_copyWorks() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.serializeParameters(new TestParameters1())).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_formatSerializer() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();
    builder.registerParametersSerializer(
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToProto, TestParameters1.class));
    assertThrows(
        GeneralSecurityException.class, () -> registry1.serializeParameters(new TestParameters1()));
    assertThrows(
        GeneralSecurityException.class, () -> registry2.serializeParameters(new TestParameters1()));
  }

  // ====================================================================== Parameters parsing tests
  @Test
  public void test_registerParametersParserAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersParser(
                ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1))
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.parseParameters(serialization)).isNotNull();
  }

  @Test
  public void test_formatParse_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry.hasParserForParameters(serialization)).isFalse();
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void test_registerSameParametersParserTwice_works() throws Exception {
    ParametersParser testParser =
        ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerParametersParser(testParser)
        .registerParametersParser(testParser)
        .build();
  }

  @Test
  public void test_registerDifferentParsersWithSameParametersType_throws() throws Exception {
    ParametersParser testParser1 =
        ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1);
    ParametersParser testParser2 =
        ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerParametersParser(testParser1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerParametersParser(testParser2));
  }

  @Test
  public void test_registerDifferentParametersParsersWithDifferentKeyType_works() throws Exception {
    ParametersParser testParser1 =
        ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1);
    ParametersParser testParser2 =
        ParametersParser.create(SerializationRegistryTest::parseProtoToParameters2, A_2);
    SerializationRegistry unused = new SerializationRegistry.Builder()
        .registerParametersParser(testParser1)
        .registerParametersParser(testParser2)
        .build();
  }

  @Test
  public void test_registerAllParametersParsers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersParser(
                ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1))
            .registerParametersParser(
                ParametersParser.create(SerializationRegistryTest::parseProtoToParameters2, A_2))
            .build();
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(TYPE_URL_2, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry.parseParameters(serialization1)).isInstanceOf(TestParameters1.class);
    assertThat(registry.parseParameters(serialization2)).isInstanceOf(TestParameters2.class);
  }

  @Test
  public void test_copyWorksForParametersParsers() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersParser(
                ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry2.parseParameters(serialization)).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_formatParser() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);

    SerializationRegistry unused =
        builder
            .registerParametersParser(
                ParametersParser.create(SerializationRegistryTest::parseProtoToParameters1, A_1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> registry1.parseParameters(serialization));
    assertThrows(GeneralSecurityException.class, () -> registry2.parseParameters(serialization));
  }
}
