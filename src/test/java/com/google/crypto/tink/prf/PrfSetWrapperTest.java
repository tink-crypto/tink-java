// Copyright 2020 Google LLC
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
package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.prf.HkdfPrfParameters.HashType;
import com.google.crypto.tink.prf.internal.HkdfPrfProtoSerialization;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrfSetWrapper. */
@RunWith(JUnit4.class)
public class PrfSetWrapperTest {
  private static final int KEY_SIZE = 32;

  private static HkdfPrfKey hkdfPrfKey0;
  private static HkdfPrfKey hkdfPrfKey1;
  private static HkdfPrfKey hkdfPrfKeyFixed;

  @BeforeClass
  public static void setUp() throws Exception {
    createTestKeys();
  }

  private static void createTestKeys() throws GeneralSecurityException {
    hkdfPrfKey0 =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(KEY_SIZE)
                    .setHashType(HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(KEY_SIZE))
            .build();
    hkdfPrfKey1 =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(KEY_SIZE)
                    .setHashType(HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(KEY_SIZE))
            .build();
    hkdfPrfKeyFixed =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(KEY_SIZE)
                    .setHashType(HashType.SHA256)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"),
                    InsecureSecretKeyAccess.get()))
            .build();
  }

  @Test
  public void compute_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKeyFixed).withFixedId(42).makePrimary())
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    byte[] prs = prfSet.computePrimary(plaintext, 12);

    assertThat(prfSet.getPrfs()).hasSize(1);
    assertThat(prs).isEqualTo(Hex.decode("04f108788845580686b70d61"));
  }

  @Test
  public void compute_usesPrimaryKey() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(42).makePrimary())
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(43))
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    byte[] prs = prfSet.computePrimary(plaintext, 12);
    byte[] prsPrimary = prfSet.getPrfs().get(42).compute(plaintext, 12);

    assertThat(prfSet.getPrimaryId()).isEqualTo(42);
    assertArrayEquals(prsPrimary, prs);
  }

  @Test
  public void prfsCorrespondToCorrectKeys() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(42).makePrimary())
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(43))
            .build();
    KeysetHandle singleKeyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(43).makePrimary())
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    PrfSet singleKeyPrfSet =
        singleKeyKeysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    byte[] prs = prfSet.getPrfs().get(43).compute(plaintext, 12);
    byte[] singleKeyPrs = singleKeyPrfSet.computePrimary(plaintext, 12);

    assertArrayEquals(singleKeyPrs, prs);
  }

  @Test
  public void getPrfs_containsOnlyExistingKeys() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(42).makePrimary())
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(43))
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);

    assertThat(prfSet.getPrfs().keySet()).containsExactly(42, 43);
  }

  @Test
  public void testWithEmptyAnnotations_noMonitoring() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(42).makePrimary())
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(43))
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    byte[] unused = prfSet.computePrimary(plaintext, 12);
    unused = prfSet.getPrfs().get(42).compute(plaintext, 12);
    unused = prfSet.getPrfs().get(43).compute(plaintext, 12);

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testWithAnnotations_hasMonitoring() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();

    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle hkdfKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(5).makePrimary())
            .addEntry(KeysetHandle.importKey(hkdfPrfKey1).withFixedId(6))
            .setMonitoringAnnotations(annotations)
            .build();
    byte[] plaintext = "blah".getBytes(UTF_8);

    PrfSet prfSet = hkdfKeysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] prsPrimary = prfSet.computePrimary(plaintext, 12);
    byte[] prs5 = prfSet.getPrfs().get(5).compute(plaintext, 12);
    byte[] prs6 = prfSet.getPrfs().get(6).compute(plaintext, 12);

    assertThat(prfSet.getPrimaryId()).isEqualTo(5);

    assertThat(prfSet.getPrfs()).hasSize(2);
    assertThat(prsPrimary).hasLength(12);
    assertThat(prs5).isEqualTo(prsPrimary);
    assertThat(prsPrimary).isNotEqualTo(prs6);

    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(3);
    FakeMonitoringClient.LogEntry entry0 = logEntries.get(0);
    assertThat(entry0.getKeyId()).isEqualTo(5);
    assertThat(entry0.getPrimitive()).isEqualTo("prf");
    assertThat(entry0.getApi()).isEqualTo("compute");
    assertThat(entry0.getAnnotations()).isEqualTo(annotations);
    FakeMonitoringClient.LogEntry entry1 = logEntries.get(1);
    assertThat(entry1.getKeyId()).isEqualTo(5);
    assertThat(entry1.getPrimitive()).isEqualTo("prf");
    assertThat(entry1.getApi()).isEqualTo("compute");
    assertThat(entry1.getAnnotations()).isEqualTo(annotations);
    FakeMonitoringClient.LogEntry entry2 = logEntries.get(2);
    assertThat(entry2.getKeyId()).isEqualTo(6);
    assertThat(entry2.getPrimitive()).isEqualTo("prf");
    assertThat(entry2.getApi()).isEqualTo("compute");
    assertThat(entry2.getAnnotations()).isEqualTo(annotations);
  }

  @Immutable
  private static class AlwaysFailingPrf implements Prf {

    AlwaysFailingPrf(HkdfPrfKey key) {}

    @Override
    public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  /** Perform registrations such as HkdfKeyManager.register, but with a failing PRF */
  private static void doHkdfKeyManagerRegistrationWithFailingPrf() throws Exception {
    HkdfPrfProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(AlwaysFailingPrf::new, HkdfPrfKey.class, Prf.class));
    MutableKeyCreationRegistry.globalInstance()
        .add(HkdfPrfKeyManager.KEY_CREATOR, HkdfPrfParameters.class);
    Registry.registerKeyManager(
        LegacyKeyManagerImpl.create(
            HkdfPrfKeyManager.getKeyType(),
            Prf.class,
            KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.proto.HkdfPrfKey.parser()),
        true);
  }

  @Test
  public void testAlwaysFailingPrfWithAnnotations_hasMonitoring() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfSetWrapper.register();
    doHkdfKeyManagerRegistrationWithFailingPrf();

    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle hkdfKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hkdfPrfKey0).withFixedId(5).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();
    PrfSet prfSet = hkdfKeysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    assertThrows(GeneralSecurityException.class, () -> prfSet.computePrimary(plaintext, 12));
    assertThrows(
        GeneralSecurityException.class, () -> prfSet.getPrfs().get(5).compute(plaintext, 12));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(2);
    FakeMonitoringClient.LogFailureEntry failure0 = failures.get(0);
    assertThat(failure0.getPrimitive()).isEqualTo("prf");
    assertThat(failure0.getApi()).isEqualTo("compute");
    assertThat(failure0.getKeysetInfo().getPrimaryKeyId()).isEqualTo(5);
    assertThat(failure0.getAnnotations()).isEqualTo(annotations);
    FakeMonitoringClient.LogFailureEntry failure1 = failures.get(1);
    assertThat(failure1.getPrimitive()).isEqualTo("prf");
    assertThat(failure1.getApi()).isEqualTo("compute");
    assertThat(failure1.getKeysetInfo().getPrimaryKeyId()).isEqualTo(5);
    assertThat(failure1.getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void prfLegacyKeys() throws Exception {
    // Tink reparses keys when we use the RegistryConfiguration. See b/389599314 for a discussion
    // how to handle this.
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();
    LegacyProtoKey legacyProtoKey =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                com.google.crypto.tink.proto.HkdfPrfKey.newBuilder()
                    .setParams(
                        HkdfPrfParams.newBuilder()
                            .setHash(com.google.crypto.tink.proto.HashType.SHA256))
                    .setKeyValue(
                        ByteString.fromHex(
                            "0102030405060708091011121314151617181920212123242526272829303132"))
                    .build()
                    .toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null),
            InsecureSecretKeyAccess.get());

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(legacyProtoKey).withFixedId(42).makePrimary())
            .build();
    PrfSet prfSet = keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class);
    byte[] plaintext = new byte[] {1};
    // Same result as in PrfBasedKeyDeriverTest.java, basicTest(), where this becomes key material.
    assertArrayEquals(
        prfSet.getPrfs().get(42).compute(plaintext, 12), Hex.decode("4A8984211468FF8B78399156"));
  }

  @Test
  public void prfLegacyKeysTinkFail() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    PrfConfig.register();
    LegacyProtoKey legacyProtoKey =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                com.google.crypto.tink.proto.HkdfPrfKey.newBuilder()
                    .setParams(
                        HkdfPrfParams.newBuilder()
                            .setHash(com.google.crypto.tink.proto.HashType.SHA256))
                    .setKeyValue(
                        ByteString.fromHex(
                            "0102030405060708091011121314151617181920212123242526272829303132"))
                    .build()
                    .toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                /* idRequirement= */ 42),
            InsecureSecretKeyAccess.get());

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(legacyProtoKey).withFixedId(42).makePrimary())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(RegistryConfiguration.get(), PrfSet.class));
  }

  @Test
  public void registerToInternalPrimitiveRegistry_works() throws Exception {
    PrimitiveRegistry.Builder initialBuilder = PrimitiveRegistry.builder();
    PrimitiveRegistry initialRegistry = initialBuilder.build();
    PrimitiveRegistry.Builder processedBuilder = PrimitiveRegistry.builder(initialRegistry);

    PrfSetWrapper.registerToInternalPrimitiveRegistry(processedBuilder);
    PrimitiveRegistry processedRegistry = processedBuilder.build();

    assertThrows(
        GeneralSecurityException.class, () -> initialRegistry.getInputPrimitiveClass(PrfSet.class));
    assertThat(processedRegistry.getInputPrimitiveClass(PrfSet.class)).isEqualTo(Prf.class);
  }
}
