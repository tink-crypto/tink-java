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

package com.google.crypto.tink;

import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * An interface which provides methods to serialize and parse keys and parameters for the Tink
 * "ProtoKeyset" format.
 */
public interface ProtoKeySerializer {
  Key parseKey(ProtoKeySerialization protoKeySerialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException;

  ProtoKeySerialization serializeKey(Key key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException;

  ByteString serializeParameters(Parameters parameters) throws GeneralSecurityException;

  Parameters parseParameters(ByteString serialization) throws GeneralSecurityException;
}
