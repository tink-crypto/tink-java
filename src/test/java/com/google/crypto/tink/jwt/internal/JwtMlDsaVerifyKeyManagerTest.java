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

package com.google.crypto.tink.jwt.internal;

import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.testing.TestUtil;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JwtMlDsaVerifyKeyManager}. */
@RunWith(JUnit4.class)
public final class JwtMlDsaVerifyKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will fail or be skipped.
    }
    JwtSignatureConfig.register();
    JwtMlDsaSignKeyManager.registerPair(/* newKeyAllowed= */ true);
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }

    KeyTemplate template = KeyTemplates.get("JWT_ML_DSA_44_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template).getPublicKeysetHandle();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle, RegistryConfiguration.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(
            serializedKeyset, RegistryConfiguration.get());
    assertTrue(parsed.equalsKeyset(handle));
  }
}
