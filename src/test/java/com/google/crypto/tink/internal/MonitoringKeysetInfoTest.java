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
import java.util.HashMap;
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
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.getEntries()).hasSize(1);
    MonitoringKeysetInfo.Entry entry = info.getEntries().get(0);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.getKeyId()).isEqualTo(123);
    assertThat(entry.getKeyType()).isEqualTo("typeUrl123");
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
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .addEntry(key234, KeyStatus.ENABLED, 234, "typeUrl234")
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.getEntries()).hasSize(2);
  }

  @Test
  public void addSameEntryTwice() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .setPrimaryKeyId(123)
            .build();
    // entries are a list, so we can add the same entry twice.
    assertThat(info.getEntries()).hasSize(2);
  }

  @Test
  public void setAndGetAnnotations() throws Exception {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    HashMap<String, String> annotations = new HashMap<>();
    annotations.put("annotation_name1", "annotation_value1");
    annotations.put("annotation_name2", "annotation_value2");
    MonitoringAnnotations monitoringAnnotations =
        MonitoringAnnotations.newBuilder()
            .addAll(annotations)
            .add("annotation_name3", "annotation_value3")
            .add("annotation_name4", "annotation_value4")
            .build();
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(monitoringAnnotations)
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .setPrimaryKeyId(123)
            .build();
    HashMap<String, String> expected = new HashMap<>();
    expected.put("annotation_name1", "annotation_value1");
    expected.put("annotation_name2", "annotation_value2");
    expected.put("annotation_name3", "annotation_value3");
    expected.put("annotation_name4", "annotation_value4");
    assertThat(info.getAnnotations().toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void primaryIsNullIfItIsNotSet() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .build();
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
                .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
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
  public void entriesAreNotModifiable() throws Exception {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .setPrimaryKeyId(123)
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name", "annotation_value")
                    .build())
            .build();
    MonitoringKeysetInfo info2 =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 234, "typeUrl234")
            .setPrimaryKeyId(234)
            .build();
    assertThrows(
        UnsupportedOperationException.class,
        () -> info.getAnnotations().toMap().put("name", "value"));
    assertThrows(
        UnsupportedOperationException.class,
        () -> info.getEntries().add(info2.getEntries().get(0)));
  }

  @Test
  public void builderIsInvalidAfterBuild() throws Exception  {
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name2", "annotation_value2").build();
    MonitoringKeysetInfo.Builder builder =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .setPrimaryKeyId(123)
            .setAnnotations(annotations);
    Object unused = builder.build();
    assertThrows(IllegalStateException.class, () -> builder.setAnnotations(annotations));
    assertThrows(
        IllegalStateException.class,
        () -> builder.addEntry(key234, KeyStatus.ENABLED, 234, "typeUrl234"));
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
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .build())
            .addEntry(key123, KeyStatus.ENABLED, 123, "typeUrl123")
            .addEntry(key234, KeyStatus.DISABLED, 234, "typeUrl234")
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.toString())
        .isEqualTo(
            "(annotations={annotation_name1=annotation_value1}, entries="
                + "[(status=ENABLED, keyId=123, keyType='typeUrl123'), "
                + "(status=DISABLED, keyId=234, keyType='typeUrl234')], primaryKeyId=123)");
  }
}
