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

/** Tests for {@link KeyParser}. */
@RunWith(JUnit4.class)
public final class KeyParserTest {

  @Immutable
  private static class ExampleKey extends Key {
    @Override
    public boolean equalsKey(Key k) {
      return k == this;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return null;
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Immutable
  private static class ExampleSerialization implements Serialization {
    @Override
    public Bytes getObjectIdentifier() {
      return Bytes.copyFrom(new byte[0]);
    }
  }

  private static ExampleKey parse(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new ExampleKey();
  }

  private static ExampleKey parseExample(
      ExampleSerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return new ExampleKey();
  }

  @Test
  public void createParser_works() throws Exception {
    Object unused =
        KeyParser.create(
            KeyParserTest::parse, Bytes.copyFrom(new byte[0]), ProtoKeySerialization.class);
  }

  @Test
  public void createParser_works_2() throws Exception {
    Object unused = KeyParser.create(KeyParserTest::parse, Bytes.copyFrom(new byte[0]));
  }

  @Test
  public void createParser_parseKey_works() throws Exception {
    KeyParser<ProtoKeySerialization> parser =
        KeyParser.create(
            KeyParserTest::parse, Bytes.copyFrom(new byte[0]), ProtoKeySerialization.class);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "typeUrl",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThat(parser.parseKey(serialization, InsecureSecretKeyAccess.get())).isNotNull();
    assertThrows(
        GeneralSecurityException.class, () -> parser.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void createParser_classes_work() throws Exception {
    KeyParser<ProtoKeySerialization> parser =
        KeyParser.create(
            KeyParserTest::parse,
            Bytes.copyFrom(new byte[] {1, 2, 3}),
            ProtoKeySerialization.class);
    assertThat(parser.getObjectIdentifier()).isEqualTo(Bytes.copyFrom(new byte[] {1, 2, 3}));
    assertThat(parser.getSerializationClass()).isEqualTo(ProtoKeySerialization.class);
  }

  @Test
  public void createParser_nonProto_throws() throws Exception {
    Bytes objectIdentifier = Bytes.copyFrom(new byte[0]);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            KeyParser.create(
                KeyParserTest::parseExample, objectIdentifier, ExampleSerialization.class));
  }
}
