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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtMacWrapper. */
@RunWith(JUnit4.class)
public class JwtMacWrapperTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtMacConfig.register();
  }

  @Test
  public void test_wrapNoPrimary_throws() throws Exception {
    // The old KeysetManager API allows keysets without primary key.
    // The KeysetHandle.Builder does not allow this and can't be used in this test.
    KeyTemplate template = KeyTemplates.get("JWT_HS256");
    KeysetManager manager = KeysetManager.withEmptyKeyset().add(template);
    KeysetHandle handle = manager.getKeysetHandle();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(JwtMac.class));
  }

  @Test
  public void test_wrapLegacy_throws() throws Exception {
    KeyTemplate rawTemplate = KeyTemplates.get("JWT_HS256_RAW");
    // Convert the normal, raw template into a template with output prefix type LEGACY
    KeysetHandle handle = KeysetHandle.generateNew(rawTemplate);
    Keyset keyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()),
            ExtensionRegistryLite.getEmptyRegistry());
    Keyset.Builder legacyKeysetBuilder = keyset.toBuilder();
    legacyKeysetBuilder.setKey(
        0, legacyKeysetBuilder.getKey(0).toBuilder().setOutputPrefixType(OutputPrefixType.LEGACY));
    KeysetHandle legacyHandle =
        TinkProtoKeysetFormat.parseKeyset(
            legacyKeysetBuilder.build().toByteArray(), InsecureSecretKeyAccess.get());
    assertThrows(GeneralSecurityException.class, () -> legacyHandle.getPrimitive(JwtMac.class));
  }

  @Test
  public void test_wrapSingleRawKey_works() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_HS256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = jwtMac.computeMacAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
  }

  @Test
  public void test_wrapSingleTinkKey_works() throws Exception {
    KeyTemplate tinkTemplate = KeyTemplates.get("JWT_HS256");
    KeysetHandle handle = KeysetHandle.generateNew(tinkTemplate);
    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    RawJwt rawJwt = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
  }

  @Test
  public void test_wrapMultipleRawKeys() throws Exception {
    KeysetHandle oldHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle newHandle =
        KeysetHandle.newBuilder(oldHandle)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    JwtMac oldJwtMac = oldHandle.getPrimitive(JwtMac.class);
    JwtMac newJwtMac = newHandle.getPrimitive(JwtMac.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldJwtMac.computeMacAndEncode(rawToken);
    String newSignedCompact = newJwtMac.computeMacAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newJwtMac.verifyMacAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldJwtMac.verifyMacAndDecode(newSignedCompact, validator));
  }

  @Test
  public void test_wrapMultipleTinkKeys() throws Exception {
    KeysetHandle oldHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256")
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle newHandle =
        KeysetHandle.newBuilder(oldHandle)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256")
                    .withRandomId()
                    .makePrimary())
            .build();

    JwtMac oldJwtMac = oldHandle.getPrimitive(JwtMac.class);
    JwtMac newJwtMac = newHandle.getPrimitive(JwtMac.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldJwtMac.computeMacAndEncode(rawToken);
    String newSignedCompact = newJwtMac.computeMacAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newJwtMac.verifyMacAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldJwtMac.verifyMacAndDecode(newSignedCompact, validator));
  }

  @Test
  public void wrongKey_throwsInvalidSignatureException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256"));
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    RawJwt rawJwt = RawJwt.newBuilder().withoutExpiration().build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256"));
    JwtMac wrongJwtMac = wrongKeysetHandle.getPrimitive(JwtMac.class);
    assertThrows(
        GeneralSecurityException.class, () -> wrongJwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void wrongIssuer_throwsInvalidException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256"));
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    RawJwt rawJwt = RawJwt.newBuilder().setIssuer("Justus").withoutExpiration().build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator =
        JwtValidator.newBuilder().allowMissingExpiration().expectIssuer("Peter").build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void expiredCompact_throwsExpiredException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256"));
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void notYetValidCompact_throwsNotBeforeException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256"));
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .withoutExpiration()
            .build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void testWithoutAnnotations_hasNoMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256")
                    .makePrimary()
                    .withFixedId(42))
            .build();
    JwtMac jwtMac = keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtMac.class);
    RawJwt rawJwt = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
    assertThrows(
        GeneralSecurityException.class, () -> jwtMac.verifyMacAndDecode("invalid", validator));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_HS256")
                    .makePrimary()
                    .withFixedId(42))
            .setMonitoringAnnotations(annotations)
            .build();

    JwtMac jwtMac = keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtMac.class);
    RawJwt rawJwt = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
    assertThrows(
        GeneralSecurityException.class, () -> jwtMac.verifyMacAndDecode("invalid", validator));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry computeEntry = logEntries.get(0);
    assertThat(computeEntry.getKeyId()).isEqualTo(42);
    assertThat(computeEntry.getPrimitive()).isEqualTo("jwtmac");
    assertThat(computeEntry.getApi()).isEqualTo("compute");
    assertThat(computeEntry.getNumBytesAsInput()).isEqualTo(1);
    assertThat(computeEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry verifyEntry = logEntries.get(1);
    assertThat(verifyEntry.getKeyId()).isEqualTo(42);
    assertThat(verifyEntry.getPrimitive()).isEqualTo("jwtmac");
    assertThat(verifyEntry.getApi()).isEqualTo("verify");
    assertThat(verifyEntry.getNumBytesAsInput()).isEqualTo(1);
    assertThat(verifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("jwtmac");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
