// Copyright 2021 Google LLC
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
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for JwtSignKeyverifyWrapper. */
@RunWith(Theories.class)
public class JwtPublicKeySignVerifyWrappersTest {

  @DataPoints("templateNames")
  public static final String[] TEMPLATE_NAMES =
      new String[] {
        "JWT_ES256",
        "JWT_ES384",
        "JWT_ES512",
        "JWT_ES256_RAW",
        "JWT_RS256_2048_F4",
        "JWT_RS256_3072_F4",
        "JWT_RS384_3072_F4",
        "JWT_RS512_4096_F4",
        "JWT_RS256_2048_F4_RAW",
        "JWT_PS256_2048_F4",
        "JWT_PS256_3072_F4",
        "JWT_PS384_3072_F4",
        "JWT_PS512_4096_F4",
        "JWT_PS256_2048_F4_RAW",
      };

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtSignatureConfig.register();
  }

  @Test
  public void test_noPrimary_getSignPrimitive_fails() throws Exception {
    // The old KeysetManager API allows keysets without primary key.
    // The KeysetHandle.Builder does not allow this and can't be used in this test.
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetManager manager = KeysetManager.withEmptyKeyset().add(template);
    KeysetHandle handle = manager.getKeysetHandle();
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class));
  }

  @Test
  public void test_noPrimary_getVerifyPrimitive_success() throws Exception {
    KeysetHandle privateKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256")
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle publicHandle = privateKeysetHandle.getPublicKeysetHandle();
    Object unused =
        publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
  }

  @Test
  public void test_wrapLegacy_throws() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("JWT_ES256_RAW"));
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
    assertThrows(
        GeneralSecurityException.class,
        () -> legacyHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class));

    KeysetHandle publicHandle = legacyHandle.getPublicKeysetHandle();
    assertThrows(
        GeneralSecurityException.class,
        () -> publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class));
  }

  @Test
  public void test_wrapSingleTinkKey_works() throws Exception {
    KeyTemplate tinkTemplate = KeyTemplates.get("JWT_ES256");

    KeysetHandle handle = KeysetHandle.generateNew(tinkTemplate);

    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapSingleRawKey_works() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapMultipleRawKeys() throws Exception {
    KeysetHandle oldHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle newHandle =
        KeysetHandle.newBuilder(oldHandle)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    JwtPublicKeySign oldSigner =
        oldHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeySign newSigner =
        newHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);

    JwtPublicKeyVerify oldVerifier =
        oldHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify newVerifier =
        newHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldSigner.signAndEncode(rawToken);
    String newSignedCompact = newSigner.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldVerifier.verifyAndDecode(newSignedCompact, validator));
  }

  @Test
  public void test_wrapMultipleTinkKeys() throws Exception {
    KeysetHandle oldHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256")
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle newHandle =
        KeysetHandle.newBuilder(oldHandle)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256")
                    .withRandomId()
                    .makePrimary())
            .build();

    JwtPublicKeySign oldSigner =
        oldHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeySign newSigner =
        newHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);

    JwtPublicKeyVerify oldVerifier =
        oldHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify newVerifier =
        newHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldSigner.signAndEncode(rawToken);
    String newSignedCompact = newSigner.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldVerifier.verifyAndDecode(newSignedCompact, validator));
  }

  @Test
  public void disabledKeyIgnoredWhenVerifying() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256_RAW")
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    JwtPublicKeySign signerForDisabledKey =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(handle.getAt(0).getKey()).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signerForDisabledKey.signAndEncode(rawToken);

    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(signedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void wrongKey_throwsInvalidSignatureException(
      @FromDataPoints("templateNames") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeyTemplate template = KeyTemplates.get(templateName);
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSign =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawJwt = RawJwt.newBuilder().withoutExpiration().build();
    String compact = jwtSign.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(template);
    KeysetHandle wrongPublicKeysetHandle = wrongKeysetHandle.getPublicKeysetHandle();

    JwtPublicKeyVerify wrongJwtVerify =
        wrongPublicKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    assertThrows(
        GeneralSecurityException.class, () -> wrongJwtVerify.verifyAndDecode(compact, validator));
  }

  @Test
  public void wrongIssuer_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier =
        publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    RawJwt rawJwt = RawJwt.newBuilder().setIssuer("Justus").withoutExpiration().build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("Peter").allowMissingExpiration().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }

  @Test
  public void expiredCompact_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier =
        publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }

  @Test
  public void notYetValidCompact_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier =
        publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .withoutExpiration()
            .build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }

  /* TODO: b/252792776. All keysets without primary should be rejected in every case. */
  @Test
  public void test_verifyWithoutPrimary_works() throws Exception {
    Parameters parameters = KeyTemplates.get("JWT_ES256").toParameters();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    KeysetHandle publicHandle = handle.getPublicKeysetHandle();
    Keyset publicKeyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicHandle),
            ExtensionRegistryLite.getEmptyRegistry());
    Keyset publicKeysetWithoutPrimary = publicKeyset.toBuilder().setPrimaryKeyId(0).build();
    // TODO(b/252792776): Optimally, this would throw.
    KeysetHandle publicHandleWithoutPrimary =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(publicKeysetWithoutPrimary.toByteArray());

    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    // TODO(b/252792776): At least this should throw.
    JwtPublicKeyVerify verifier =
        publicHandleWithoutPrimary.getPrimitive(
            RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void testWithoutAnnotations_hasNoMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle privateKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256")
                    .makePrimary()
                    .withFixedId(42))
            .build();
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
    JwtPublicKeySign signer =
        privateKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawJwt = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawJwt);

    JwtPublicKeyVerify verifier =
        publicKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode("invalid", validator));

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
    KeysetHandle privateKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("JWT_ES256")
                    .makePrimary()
                    .withFixedId(42))
            .setMonitoringAnnotations(annotations)
            .build();
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
    JwtPublicKeySign signer =
        privateKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawJwt = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawJwt);

    JwtPublicKeyVerify verifier =
        publicKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("id123");
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode("invalid", validator));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry signEntry = logEntries.get(0);
    assertThat(signEntry.getKeyId()).isEqualTo(42);
    assertThat(signEntry.getPrimitive()).isEqualTo("jwtsign");
    assertThat(signEntry.getApi()).isEqualTo("sign");
    assertThat(signEntry.getNumBytesAsInput()).isEqualTo(1);
    assertThat(signEntry.getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry verifyEntry = logEntries.get(1);
    assertThat(verifyEntry.getKeyId()).isEqualTo(42);
    assertThat(verifyEntry.getPrimitive()).isEqualTo("jwtverify");
    assertThat(verifyEntry.getApi()).isEqualTo("verify");
    assertThat(verifyEntry.getNumBytesAsInput()).isEqualTo(1);
    assertThat(verifyEntry.getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("jwtverify");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getPrimary().getId()).isEqualTo(42);
    assertThat(verifyFailure.getAnnotations()).isEqualTo(annotations);
  }
}
