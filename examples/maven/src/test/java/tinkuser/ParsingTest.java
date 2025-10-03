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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

/**
 * A test for different serializations. We test this because serialization often requires special
 * dependencies (JSON/Protobuf) which one can get wrong if one isn't careful.
 */
public class ParsingTest {
  @Test
  public void serializeAndParseProtobuf() throws GeneralSecurityException {
    AeadConfig.register();
    KeysetHandle keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);

    byte[] b = TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed = TinkProtoKeysetFormat.parseKeyset(b, InsecureSecretKeyAccess.get());
    if (!keysetHandle.equalsKeyset(parsed)) {
      throw new GeneralSecurityException("Differences found!");
    }
  }

  @Test
  public void serializeAndParseJsonProto() throws GeneralSecurityException {
    AeadConfig.register();
    KeysetHandle keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);

    String s =
        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed = TinkJsonProtoKeysetFormat.parseKeyset(s, InsecureSecretKeyAccess.get());
    if (!keysetHandle.equalsKeyset(parsed)) {
      throw new GeneralSecurityException("Differences found!");
    }
  }
}
