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
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link MutableSerializationRegistry}.
 *
 * <p>We repeat the main tests in SerializationRegistryTest. There really shouldn't be both classes,
 * but currently this is what we need, and the other is what we should have.
 */
@RunWith(JUnit4.class)
public final class MutableSerializationRegistryTest {
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
  public void test_registerAllSerializers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey1ToProto,
            TestKey1.class,
            ProtoKeySerialization.class));
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey2ToProto,
            TestKey2.class,
            ProtoKeySerialization.class));
    assertThat(registry.hasSerializerForKey(new TestKey1(), ProtoKeySerialization.class)).isTrue();
    assertThat(
            registry.serializeKey(new TestKey1(), ProtoKeySerialization.class, ACCESS).getTypeUrl())
        .isEqualTo(TYPE_URL_1);
    assertThat(
            registry.serializeKey(new TestKey2(), ProtoKeySerialization.class, ACCESS).getTypeUrl())
        .isEqualTo(TYPE_URL_2);
  }

  @Test
  public void emptyRegistry_serializeKey_throws() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    assertThat(registry.hasSerializerForKey(new TestKey1(), ProtoKeySerialization.class)).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(new TestKey1(), ProtoKeySerialization.class, ACCESS));
  }

  @Test
  public void test_registerAllParsers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseProtoToKey1, A_1, ProtoKeySerialization.class));
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseProtoToKey2, A_2, ProtoKeySerialization.class));
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
    assertThat(registry.hasParserForKey(serialization1)).isTrue();
    assertThat(registry.parseKey(serialization1, ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(serialization2, ACCESS)).isInstanceOf(TestKey2.class);
  }

  @Test
  public void emptyRegistry_parseKey_throws() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
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

  @Test
  public void test_registerAllParametersSerializers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters1ToProto,
            TestParameters1.class,
            ProtoParametersSerialization.class));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters2ToProto,
            TestParameters2.class,
            ProtoParametersSerialization.class));
    assertThat(
            registry.hasSerializerForParameters(
                new TestParameters1(), ProtoParametersSerialization.class))
        .isTrue();
    assertThat(
            registry
                .serializeParameters(new TestParameters1(), ProtoParametersSerialization.class)
                .getTypeUrl())
        .isEqualTo(TYPE_URL_1);
    assertThat(
            registry
                .serializeParameters(new TestParameters2(), ProtoParametersSerialization.class)
                .getTypeUrl())
        .isEqualTo(TYPE_URL_2);
  }

  @Test
  public void emptyRegistry_serializeParameters_throws() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    assertThat(
            registry.hasSerializerForParameters(
                new TestParameters1(), ProtoParametersSerialization.class))
        .isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.serializeParameters(
                new TestParameters1(), ProtoParametersSerialization.class));
  }

  @Test
  public void test_registerAllParametersParsers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseProtoToParameters1,
            A_1,
            ProtoParametersSerialization.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseProtoToParameters2,
            A_2,
            ProtoParametersSerialization.class));
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(TYPE_URL_2, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry.hasParserForParameters(serialization1)).isTrue();
    assertThat(registry.parseParameters(serialization1)).isInstanceOf(TestParameters1.class);
    assertThat(registry.parseParameters(serialization2)).isInstanceOf(TestParameters2.class);
  }

  @Test
  public void emptyRegistry_parseParameters_throws() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(TYPE_URL_1, OutputPrefixType.RAW, ByteString.EMPTY);
    assertThat(registry.hasParserForParameters(serialization)).isFalse();
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void test_parseParametersWithLegacyFallback_testFallback() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            "typeUrlForTesting73107",
            OutputPrefixType.TINK,
            TestProto.getDefaultInstance().toByteString());
    Parameters parameters = registry.parseParametersWithLegacyFallback(protoParameters);
    assertThat(parameters).isInstanceOf(LegacyProtoParameters.class);
    LegacyProtoParameters legacyProtoParameters = (LegacyProtoParameters) parameters;
    assertThat(legacyProtoParameters.getSerialization().getKeyTemplate().getTypeUrl())
        .isEqualTo("typeUrlForTesting73107");
  }

  private static TestParameters1 parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return new TestParameters1();
  }

  private static TestParameters1 parseParametersAlwaysThrows(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    throw new GeneralSecurityException("Always throws");
  }

  @Test
  public void test_parseParametersWithLegacyFallback_testRegistered() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseParameters,
            Util.toBytesFromPrintableAscii("typeUrlForTesting98178"),
            ProtoParametersSerialization.class));
    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            "typeUrlForTesting98178",
            OutputPrefixType.TINK,
            TestProto.getDefaultInstance().toByteString());
    Parameters parameters = registry.parseParametersWithLegacyFallback(protoParameters);
    assertThat(parameters).isInstanceOf(TestParameters1.class);
  }

  @Test
  public void test_parseParametersWithLegacyFallback_testRegisteredButFaulty_throws()
      throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseParametersAlwaysThrows,
            Util.toBytesFromPrintableAscii("typeUrlForTesting98178"),
            ProtoParametersSerialization.class));
    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            "typeUrlForTesting98178",
            OutputPrefixType.TINK,
            TestProto.getDefaultInstance().toByteString());
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseParametersWithLegacyFallback(protoParameters));
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testFallback() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting21125",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    Key key = registry.parseKeyWithLegacyFallback(protoKey, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    LegacyProtoKey legacyProtoKey = (LegacyProtoKey) key;
    assertThat(legacyProtoKey.getSerialization(InsecureSecretKeyAccess.get()).getTypeUrl())
        .isEqualTo("typeUrlForTesting21125");
  }

  private static TestKey1 parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return new TestKey1();
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testRegistered() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseKey,
            Util.toBytesFromPrintableAscii("typeUrlForTesting18412"),
            ProtoKeySerialization.class));
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting18412",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    Key key = registry.parseKeyWithLegacyFallback(protoKey, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(TestKey1.class);
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testFallback_missingAccess() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting21125",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKeyWithLegacyFallback(protoKey, null));
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testFallback_accessNotNeededRemote()
      throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting21125",
            ByteString.EMPTY,
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    Key key = registry.parseKeyWithLegacyFallback(protoKey, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(LegacyProtoKey.class);
  }
}
