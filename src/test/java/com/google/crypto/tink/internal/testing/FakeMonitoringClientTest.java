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

package com.google.crypto.tink.internal.testing;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.util.SecretBytes;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeMonitoringClientTest {
  @BeforeClass
  public static void register() throws Exception {
    TinkConfig.register();
  }

  @Test
  public void log() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    KeysetHandleInterface keysetInfo =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key123)
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(123)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(key234).setStatus(KeyStatus.ENABLED).withFixedId(234))
            .build();
    MonitoringClient.Logger encLogger =
        client.createLogger(
            keysetInfo,
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build(),
            "aead",
            "encrypt");

    encLogger.log(123, 42);

    assertThat(client.getLogFailureEntries()).isEmpty();
    List<FakeMonitoringClient.LogEntry> logEntries = client.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry logEntry = logEntries.get(0);
    assertThat(logEntry.getKeysetInfo()).isEqualTo(keysetInfo);
    assertThat(logEntry.getKeyInfo()).isEqualTo(keysetInfo.getAt(0));
    assertThat(logEntry.getPrimitive()).isEqualTo("aead");
    assertThat(logEntry.getApi()).isEqualTo("encrypt");
    assertThat(logEntry.getKeyId()).isEqualTo(123);
    assertThat(logEntry.getNumBytesAsInput()).isEqualTo(42);
    assertThat(logEntry.getAnnotations())
        .isEqualTo(
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build());

    client.clear();
    assertThat(client.getLogEntries()).isEmpty();
  }

  @Test
  public void logFailure() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    KeysetHandleInterface keysetInfo =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key234)
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(234)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(key123).setStatus(KeyStatus.ENABLED).withFixedId(123))
            .build();
    MonitoringClient.Logger encLogger =
        client.createLogger(
            keysetInfo,
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build(),
            "aead",
            "encrypt");

    encLogger.logFailure();

    assertThat(client.getLogEntries()).isEmpty();
    List<FakeMonitoringClient.LogFailureEntry> logFailureEntries = client.getLogFailureEntries();
    assertThat(logFailureEntries).hasSize(1);
    FakeMonitoringClient.LogFailureEntry logFailureEntry = logFailureEntries.get(0);
    assertThat(logFailureEntry.getKeysetInfo()).isEqualTo(keysetInfo);
    assertThat(logFailureEntry.getPrimitive()).isEqualTo("aead");
    assertThat(logFailureEntry.getApi()).isEqualTo("encrypt");
    assertThat(logFailureEntry.getAnnotations())
        .isEqualTo(
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build());

    client.clear();
    assertThat(client.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void logKeyExport() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    KeysetHandleInterface keysetInfo =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key123)
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(123)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(key234).setStatus(KeyStatus.ENABLED).withFixedId(234))
            .build();
    MonitoringClient.Logger encLogger =
        client.createLogger(
            keysetInfo,
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build(),
            "aead",
            "encrypt");

    assertThat(client.getLogKeyExportEntries()).isEmpty();
    encLogger.logKeyExport(123);

    List<FakeMonitoringClient.LogKeyExportEntry> logEntries = client.getLogKeyExportEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogKeyExportEntry logEntry = logEntries.get(0);
    assertThat(logEntry.getKeysetInfo()).isEqualTo(keysetInfo);
    assertThat(logEntry.getKeyInfo()).isEqualTo(keysetInfo.getAt(0));
    assertThat(logEntry.getPrimitive()).isEqualTo("aead");
    assertThat(logEntry.getApi()).isEqualTo("encrypt");
    assertThat(logEntry.getKeyId()).isEqualTo(123);
    assertThat(logEntry.getAnnotations())
        .isEqualTo(
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build());

    client.clear();
    assertThat(client.getLogKeyExportEntries()).isEmpty();
  }

  @Test
  public void twoLoggers() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    ChaCha20Poly1305Key key234 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 234);
    KeysetHandleInterface info =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key234)
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(234)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(key123).setStatus(KeyStatus.ENABLED).withFixedId(123))
            .build();
    MonitoringClient.Logger encLogger =
        client.createLogger(
            info,
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build(),
            "aead",
            "encrypt");
    MonitoringClient.Logger decLogger =
        client.createLogger(
            info,
            MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build(),
            "aead",
            "decrypt");

    encLogger.log(123, 42);
    decLogger.log(234, 18);
    decLogger.logFailure();

    List<FakeMonitoringClient.LogEntry> logEntries = client.getLogEntries();
    List<FakeMonitoringClient.LogFailureEntry> logFailureEntries = client.getLogFailureEntries();
    assertThat(logEntries).hasSize(2);
    assertThat(logFailureEntries).hasSize(1);
    assertThat(logEntries.get(0).getApi()).isEqualTo("encrypt");
    assertThat(logEntries.get(1).getApi()).isEqualTo("decrypt");
    assertThat(logFailureEntries.get(0).getApi()).isEqualTo("decrypt");
  }


  @Test
  public void logWrongKeyIdFails() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    ChaCha20Poly1305Key key123 =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 123);
    KeysetHandleInterface info =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key123)
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(123)
                    .makePrimary())
            .build();
    MonitoringClient.Logger encLogger =
        client.createLogger(info, MonitoringAnnotations.EMPTY, "aead", "encrypt");

    assertThrows(IllegalStateException.class, () -> encLogger.log(1234, 42));
    assertThrows(IllegalStateException.class, () -> encLogger.logKeyExport(1234));
  }
}
