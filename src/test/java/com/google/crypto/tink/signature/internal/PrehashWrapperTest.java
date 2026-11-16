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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaMuTestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaMuTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrehashWrapperTest {
  private static final List<MlDsaMuTestVector> muTestVectors =
      MlDsaMuTestUtil.createMlDsaMuTestVectors();

  @BeforeClass
  public static void setUp() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Before
  public void assumeMlDsaIsSupported() {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    Assume.assumeTrue(MlDsaPrehashConscrypt.isSupported());
  }

  private static MlDsaPublicKey createTinkPublicKey(MlDsaMuTestVector testVector, int idRequirement)
      throws GeneralSecurityException {
    return MlDsaPublicKey.builder()
        .setParameters(MlDsaParameters.create(testVector.getInstance(), Variant.TINK))
        .setSerializedPublicKey(
            com.google.crypto.tink.util.Bytes.copyFrom(testVector.getPublicKeyBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  private static MlDsaPublicKey createNoPrefixPublicKey(MlDsaMuTestVector testVector)
      throws GeneralSecurityException {
    return MlDsaPublicKey.builder()
        .setParameters(MlDsaParameters.create(testVector.getInstance(), Variant.NO_PREFIX))
        .setSerializedPublicKey(
            com.google.crypto.tink.util.Bytes.copyFrom(testVector.getPublicKeyBytes()))
        .build();
  }

  // PrehashWrapper is created from a keyset of public keys.
  private static Prehash createMlDsaPrehash(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    return MlDsaPrehashConscrypt.create((MlDsaPublicKey) entry.getKey());
  }

  private static final class AlwaysFailingPrehash implements Prehash {
    @Override
    public byte[] compute(final byte[] data) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Test
  public void compute_usesPrimaryKey() throws Exception {
    MlDsaMuTestVector primaryVector = muTestVectors.get(1);
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(0), 0x01020304))
                    .withFixedId(0x01020304))
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(primaryVector, 0x05060708))
                    .withFixedId(0x05060708)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(2), 0x090a0b0c))
                    .withFixedId(0x090a0b0c))
            .build();

    Prehash prehash = PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash);

    // The prehash value is the prehash prefix of the primary key followed by the expected mu.
    assertThat(prehash.compute(primaryVector.getMessage()))
        .isEqualTo(Bytes.concat(Hex.decode("ff05060708"), primaryVector.getMu()));
  }

  @Test
  public void wrap_disabledKeyWithoutIdRequirement_works() throws Exception {
    MlDsaMuTestVector primaryVector = muTestVectors.get(1);
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(primaryVector, 0x01020304))
                    .withFixedId(0x01020304)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(createNoPrefixPublicKey(muTestVectors.get(0)))
                    .withFixedId(0x05060708)
                    .setStatus(KeyStatus.DISABLED))
            .build();

    Prehash prehash = PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash);

    assertThat(prehash.compute(primaryVector.getMessage()))
        .isEqualTo(Bytes.concat(Hex.decode("ff01020304"), primaryVector.getMu()));
  }

  @Test
  public void wrap_primaryKeyWithoutIdRequirement_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createNoPrefixPublicKey(muTestVectors.get(1)))
                    .withFixedId(0x01020304)
                    .makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash));
  }

  @Test
  public void wrap_enabledNonPrimaryKeyWithoutIdRequirement_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(1), 0x01020304))
                    .withFixedId(0x01020304)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(createNoPrefixPublicKey(muTestVectors.get(0)))
                    .withFixedId(0x05060708))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash));
  }

  @Test
  public void compute_withoutAnnotations_doesNotMonitor() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(1), 0x01020304))
                    .withFixedId(0x01020304)
                    .makePrimary())
            .build();
    Prehash prehash = PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash);
    Object unused = prehash.compute("data".getBytes(UTF_8));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void compute_withAnnotations_logsPrimaryKeyId() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(0), 123))
                    .withFixedId(123))
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(1), 456))
                    .withFixedId(456)
                    .makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    Prehash prehash = PrehashWrapper.wrap(handle, PrehashWrapperTest::createMlDsaPrehash);

    byte[] data = "data".getBytes(UTF_8);
    Object unused = prehash.compute(data);

    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry logEntry = logEntries.get(0);
    assertThat(logEntry.getKeyId()).isEqualTo(456);
    assertThat(logEntry.getPrimitive()).isEqualTo("prehash");
    assertThat(logEntry.getApi()).isEqualTo("compute");
    assertThat(logEntry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(logEntry.getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void compute_failingPrimitiveWithAnnotations_logsFailure() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(createTinkPublicKey(muTestVectors.get(1), 123))
                    .withFixedId(123)
                    .makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    Prehash prehash = PrehashWrapper.wrap(handle, entry -> new AlwaysFailingPrehash());

    assertThrows(GeneralSecurityException.class, () -> prehash.compute("data".getBytes(UTF_8)));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry failure = failures.get(0);
    assertThat(failure.getPrimitive()).isEqualTo("prehash");
    assertThat(failure.getApi()).isEqualTo("compute");
    assertThat(failure.getKeysetInfo().getPrimary().getId()).isEqualTo(123);
    assertThat(failure.getAnnotations()).isEqualTo(annotations);
  }
}
