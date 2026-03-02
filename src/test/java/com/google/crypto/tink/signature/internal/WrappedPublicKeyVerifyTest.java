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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class WrappedPublicKeyVerifyTest {
  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
  }

  private static PublicKeyVerify createPublicKeyVerify(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof EcdsaPublicKey) {
      return EcdsaVerifyJce.create((EcdsaPublicKey) key);
    }
    throw new GeneralSecurityException("Unknown key class: " + key.getClass());
  }

  @Test
  public void verifyNoPrefix_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier =
        WrappedPublicKeyVerify.create(
            handle.getPublicKeysetHandle(), WrappedPublicKeyVerifyTest::createPublicKeyVerify);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void verifyTink_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier =
        WrappedPublicKeyVerify.create(
            handle.getPublicKeysetHandle(), WrappedPublicKeyVerifyTest::createPublicKeyVerify);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void verifyKeySelection_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    PublicKeySign signer1 = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(0).getKey());
    PublicKeySign signer2 = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(1).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig1 = signer1.sign(data);
    byte[] sig2 = signer2.sign(data);

    PublicKeyVerify verifier =
        WrappedPublicKeyVerify.create(
            publicHandle, WrappedPublicKeyVerifyTest::createPublicKeyVerify);

    verifier.verify(sig1, data);
    verifier.verify(sig2, data);
  }

  @Test
  public void verifyWithMonitoring_works() throws Exception {
    FakeMonitoringClient monitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(monitoringClient);

    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(42).makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();

    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier =
        WrappedPublicKeyVerify.create(
            handle.getPublicKeysetHandle(), WrappedPublicKeyVerifyTest::createPublicKeyVerify);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);

    List<FakeMonitoringClient.LogEntry> logEntries = monitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry entry = logEntries.get(0);
    assertThat(entry.getAnnotations()).isEqualTo(annotations);
    assertThat(entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(entry.getApi()).isEqualTo("verify");
    assertThat(entry.getKeyId()).isEqualTo(42);
    assertThat(entry.getNumBytesAsInput()).isEqualTo(data.length);

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(sig, "invalid".getBytes(UTF_8)));
    assertThat(monitoringClient.getLogFailureEntries()).hasSize(1);
    FakeMonitoringClient.LogFailureEntry failureEntry =
        monitoringClient.getLogFailureEntries().get(0);
    assertThat(failureEntry.getAnnotations()).isEqualTo(annotations);
    assertThat(failureEntry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(failureEntry.getApi()).isEqualTo("verify");
  }
}
