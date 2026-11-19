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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.SignPrehash;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class SignPrehashWrapperTest {
  // ML-DSA is the only key type which supports SignPrehash. The MlDsaTestUtil test vectors contain
  // the precomputed prehash values of their messages for the requested key IDs. Keys which are
  // used in the same keyset need different IDs.
  private static final SignatureTestVector TINK_ML_DSA_44_VECTOR =
      MlDsaTestUtil.getMlDsaValidSignatureTestVector(
          MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK), 0x12345678);
  private static final SignatureTestVector TINK_ML_DSA_65_VECTOR =
      MlDsaTestUtil.getMlDsaValidSignatureTestVector(
          MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK), 0x05060708);
  private static final SignatureTestVector TINK_ML_DSA_87_VECTOR =
      MlDsaTestUtil.getMlDsaValidSignatureTestVector(
          MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK), 0x80000000);
  private static final SignatureTestVector NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_VECTOR =
      MlDsaTestUtil.getMlDsaValidSignatureTestVector(
          MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX_WITH_PREHASH_ID),
          0x12345678);

  private static final MlDsaPrivateKey TINK_ML_DSA_44_PRIVATE_KEY =
      (MlDsaPrivateKey) TINK_ML_DSA_44_VECTOR.getPrivateKey();
  private static final byte[] tinkMlDsa44Prehash = TINK_ML_DSA_44_VECTOR.getPrehash().get();
  private static final MlDsaPrivateKey TINK_ML_DSA_65_PRIVATE_KEY =
      (MlDsaPrivateKey) TINK_ML_DSA_65_VECTOR.getPrivateKey();
  private static final byte[] tinkMlDsa65Prehash = TINK_ML_DSA_65_VECTOR.getPrehash().get();
  private static final MlDsaPrivateKey TINK_ML_DSA_87_PRIVATE_KEY =
      (MlDsaPrivateKey) TINK_ML_DSA_87_VECTOR.getPrivateKey();
  private static final byte[] tinkMlDsa87Prehash = TINK_ML_DSA_87_VECTOR.getPrehash().get();
  private static final MlDsaPrivateKey NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY =
      (MlDsaPrivateKey) NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_VECTOR.getPrivateKey();
  private static final byte[] noPrefixWithPrehashIdMlDsa65Prehash =
      NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_VECTOR.getPrehash().get();
  private static final MlDsaPrivateKey NO_PREFIX_PRIVATE_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
              .getPrivateKey();

  @BeforeClass
  public static void setUp() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Before
  public void assumeMlDsaIsSupported() {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    Assume.assumeTrue(MlDsaSignPrehashConscrypt.isSupported());
  }

  private static SignPrehash createMlDsaSignPrehash(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    return MlDsaSignPrehashConscrypt.create((MlDsaPrivateKey) entry.getKey());
  }

  private static final class AlwaysFailingSignPrehash implements SignPrehash {
    @Override
    public byte[] sign(final byte[] prehash) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Test
  public void sign_usesKeyWithIdInPrehashPrefix() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(TINK_ML_DSA_65_PRIVATE_KEY).withFixedId(0x05060708))
            .addEntry(KeysetHandle.importKey(TINK_ML_DSA_87_PRIVATE_KEY).withFixedId(0x80000000))
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    // The signer signs each prehash value with the key whose ID is in the prehash prefix, also if
    // that key is not the primary key, e.g. during a key rotation.
    byte[] signature1 = signer.sign(tinkMlDsa44Prehash);
    byte[] signature2 = signer.sign(tinkMlDsa65Prehash);
    byte[] signature3 = signer.sign(tinkMlDsa87Prehash);

    // The output prefix of each signature identifies the key which signed it.
    assertThat(Hex.encode(signature1)).startsWith("0112345678");
    assertThat(Hex.encode(signature2)).startsWith("0105060708");
    assertThat(Hex.encode(signature3)).startsWith("0180000000");
    verifier.verify(signature1, TINK_ML_DSA_44_VECTOR.getMessage());
    verifier.verify(signature2, TINK_ML_DSA_65_VECTOR.getMessage());
    verifier.verify(signature3, TINK_ML_DSA_87_VECTOR.getMessage());
  }

  @Test
  public void sign_unknownKeyId_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);

    // The prehash value of a key with the ID 0x05060708, which is not in the keyset.
    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkMlDsa65Prehash));
  }

  @Test
  public void sign_disabledKey_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_65_PRIVATE_KEY)
                    .withFixedId(0x05060708)
                    .setStatus(KeyStatus.DISABLED))
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);

    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkMlDsa65Prehash));
  }

  @Test
  public void sign_prehashShorterThanPrefix_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);

    assertThrows(GeneralSecurityException.class, () -> signer.sign(new byte[0]));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(Hex.decode("ff")));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(Hex.decode("ff123456")));
  }

  @Test
  public void sign_wrongStartByte_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    byte[] mu = Arrays.copyOfRange(tinkMlDsa44Prehash, 5, tinkMlDsa44Prehash.length);

    // The prehash prefix 0xff || 0x12345678 is replaced by the Tink output prefix
    // 0x01 || 0x12345678 and by the legacy output prefix 0x00 || 0x12345678 of the same key: the
    // key ID matches, but output prefixes are not prehash prefixes.
    byte[] tinkPrefixed = Bytes.concat(Hex.decode("0112345678"), mu);
    byte[] legacyPrefixed = Bytes.concat(Hex.decode("0012345678"), mu);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkPrefixed));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(legacyPrefixed));
  }

  @Test
  public void sign_noPrefixWithPrehashIdKey_outputsSignatureWithoutPrefix() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_65_PRIVATE_KEY)
                    .withFixedId(0x05060708)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY)
                    .withFixedId(0x12345678))
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    // The prehash value identifies the key by its prehash prefix.
    assertThat(Hex.encode(noPrefixWithPrehashIdMlDsa65Prehash)).startsWith("ff12345678");
    byte[] signature = signer.sign(noPrefixWithPrehashIdMlDsa65Prehash);

    // The signature has no output prefix: it is a plain ML-DSA-65 signature of the message.
    assertThat(signature).hasLength(3309);
    verifier.verify(signature, NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_VECTOR.getMessage());
    // In contrast, the signature of the TINK key starts with its output prefix.
    byte[] tinkSignature = signer.sign(tinkMlDsa65Prehash);
    assertThat(tinkSignature).hasLength(5 + 3309);
    assertThat(Hex.encode(Arrays.copyOf(tinkSignature, 5))).isEqualTo("0105060708");
    verifier.verify(tinkSignature, TINK_ML_DSA_65_VECTOR.getMessage());
  }

  @Test
  public void sign_noPrefixWithPrehashIdPrimaryKey_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    byte[] signature = signer.sign(noPrefixWithPrehashIdMlDsa65Prehash);

    assertThat(signature).hasLength(3309);
    verifier.verify(signature, NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_VECTOR.getMessage());
  }

  @Test
  public void sign_noPrefixWithPrehashIdKey_checksIdInPrehashPrefix() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    byte[] mu =
        Arrays.copyOfRange(
            noPrefixWithPrehashIdMlDsa65Prehash, 5, noPrefixWithPrehashIdMlDsa65Prehash.length);

    // Although the key does not output a prefix, its ID in the prehash prefix is checked:
    // - the prehash prefix 0xff || 0x05060708 refers to a key ID which is not in the keyset,
    byte[] unknownKeyId = Bytes.concat(Hex.decode("ff05060708"), mu);
    // - the Tink output prefix 0x01 || 0x12345678 of the key ID is not a prehash prefix,
    byte[] tinkPrefixed = Bytes.concat(Hex.decode("0112345678"), mu);
    // - and mu without any prefix is not a valid prehash value.
    assertThrows(GeneralSecurityException.class, () -> signer.sign(unknownKeyId));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkPrefixed));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(mu));
  }

  @Test
  public void wrap_disabledKeyWithoutIdRequirement_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(NO_PREFIX_PRIVATE_KEY)
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    verifier.verify(signer.sign(tinkMlDsa44Prehash), TINK_ML_DSA_44_VECTOR.getMessage());
  }

  @Test
  public void wrap_primaryKeyWithoutIdRequirement_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash));
  }

  @Test
  public void wrap_enabledNonPrimaryKeyWithoutIdRequirement_throws() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(NO_PREFIX_PRIVATE_KEY).withRandomId())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash));
  }

  @Test
  public void sign_withoutAnnotations_doesNotMonitor() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);
    Object unused = signer.sign(tinkMlDsa44Prehash);
    // A failure: the prehash value of a key with the ID 0x05060708, which is not in the keyset.
    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkMlDsa65Prehash));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void sign_withAnnotations_logsIdOfSigningKey() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(TINK_ML_DSA_65_PRIVATE_KEY).withFixedId(0x05060708))
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);

    // Signs with the non-primary key.
    Object unused = signer.sign(tinkMlDsa65Prehash);

    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry logEntry = logEntries.get(0);
    assertThat(logEntry.getKeyId()).isEqualTo(0x05060708);
    assertThat(logEntry.getPrimitive()).isEqualTo("prehash_signer");
    assertThat(logEntry.getApi()).isEqualTo("sign");
    assertThat(logEntry.getNumBytesAsInput()).isEqualTo(tinkMlDsa65Prehash.length);
    assertThat(logEntry.getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void sign_invalidPrehashWithAnnotations_logsFailures() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    SignPrehash signer =
        SignPrehashWrapper.wrap(handle, SignPrehashWrapperTest::createMlDsaSignPrehash);

    // Too short, wrong start byte (the Tink output prefix 0x01 || 0x12345678 of the key instead
    // of its prehash prefix), unknown key ID (the prehash value of a key with the ID 0x05060708,
    // which is not in the keyset), all rejected by the wrapper, and a truncated prehash value with
    // a valid prefix (rejected by the primitive of the key).
    byte[] wrongStartByte =
        Bytes.concat(
            Hex.decode("0112345678"),
            Arrays.copyOfRange(tinkMlDsa44Prehash, 5, tinkMlDsa44Prehash.length));
    byte[] truncated = Arrays.copyOf(tinkMlDsa44Prehash, tinkMlDsa44Prehash.length - 1);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(Hex.decode("ff123456")));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(wrongStartByte));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkMlDsa65Prehash));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(truncated));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(4);
    for (FakeMonitoringClient.LogFailureEntry failure : failures) {
      assertThat(failure.getPrimitive()).isEqualTo("prehash_signer");
      assertThat(failure.getApi()).isEqualTo("sign");
      assertThat(failure.getAnnotations()).isEqualTo(annotations);
    }
  }

  @Test
  public void sign_failingPrimitiveWithAnnotations_logsFailure() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(TINK_ML_DSA_44_PRIVATE_KEY)
                    .withFixedId(0x12345678)
                    .makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    SignPrehash signer = SignPrehashWrapper.wrap(handle, entry -> new AlwaysFailingSignPrehash());

    assertThrows(GeneralSecurityException.class, () -> signer.sign(tinkMlDsa44Prehash));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry failure = failures.get(0);
    assertThat(failure.getPrimitive()).isEqualTo("prehash_signer");
    assertThat(failure.getApi()).isEqualTo("sign");
    assertThat(failure.getKeysetInfo().getPrimary().getId()).isEqualTo(0x12345678);
    assertThat(failure.getAnnotations()).isEqualTo(annotations);
  }
}
