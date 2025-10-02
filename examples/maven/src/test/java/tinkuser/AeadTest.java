// Copyright 2025 Google LLC
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

package tinkuser;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

/**
 * A test for Aead. From Maven's perspective, we're testing the package tinkuser -- of course in
 * practice we're really just testing Tink here.
 */
public class AeadTest {
  @Test
  public void encryptThenDecryptWorks() throws GeneralSecurityException {
    AeadConfig.register();
    byte[] plaintext = "Hello World".getBytes(UTF_8);
    KeysetHandle keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
    Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] ciphertext = aead.encrypt(plaintext, new byte[] {1, 2, 3});
    byte[] decryption = aead.decrypt(ciphertext, new byte[] {1, 2, 3});
  }
}
