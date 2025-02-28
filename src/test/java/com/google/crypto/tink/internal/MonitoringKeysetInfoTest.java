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

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests MonitoringKeysetInfo */
@RunWith(JUnit4.class)
public final class MonitoringKeysetInfoTest {

  Parameters makeLegacyProtoParameters(String typeUrl) {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY)
            .build();
    ProtoParametersSerialization serialization = ProtoParametersSerialization.create(template);
    return new LegacyProtoParameters(serialization);
  }

  @Test
  public void addAndGetEntry() throws Exception {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.size()).isEqualTo(1);
    MonitoringKeysetInfo.Entry entry = info.getAt(0);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.getId()).isEqualTo(123);
    assertThat(entry.getKey().equalsKey(key123)).isTrue();
  }

  @Test
  public void addEntries() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .addEntry(key234, KeyStatus.ENABLED, 234)
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.size()).isEqualTo(2);
  }

  @Test
  public void addSameEntryTwice() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .setPrimaryKeyId(123)
            .build();
    // entries are a list, so we can add the same entry twice.
    assertThat(info.size()).isEqualTo(2);
  }

  @Test
  public void primaryIsNullIfItIsNotSet() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder().addEntry(key123, KeyStatus.ENABLED, 123).build();
    assertThat(info.getPrimaryKeyId()).isNull();
  }

  @Test
  public void primaryKeyMustBePresentInEntries() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MonitoringKeysetInfo.newBuilder()
                .addEntry(key123, KeyStatus.ENABLED, 123)
                .setPrimaryKeyId(124)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MonitoringKeysetInfo.newBuilder()
                .setPrimaryKeyId(124)
                .build());
  }

  @Test
  public void builderIsInvalidAfterBuild() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    MonitoringKeysetInfo.Builder builder =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .setPrimaryKeyId(123);
    Object unused = builder.build();
    assertThrows(
        IllegalStateException.class, () -> builder.addEntry(key234, KeyStatus.ENABLED, 234));
    assertThrows(IllegalStateException.class, () -> builder.setPrimaryKeyId(123));
  }

  @Test
  public void toStringConversion()  throws Exception {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123)
            .addEntry(key234, KeyStatus.DISABLED, 234)
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.toString())
        .isEqualTo(
            "(entries="
                + "[(status=ENABLED, keyId=123), "
                + "(status=DISABLED, keyId=234)], primaryKeyId=123)");
  }
}
