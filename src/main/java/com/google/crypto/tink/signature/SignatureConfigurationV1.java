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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Configuration;
import com.google.errorprone.annotations.InlineMe;
import java.security.GeneralSecurityException;

/**
 * SignatureConfigurationV1 is a wrapper around SignatureConfig2026 for backward compatibility.
 * It is not exposed to OSS.
 */
/* Placeholder for internally public; DO NOT CHANGE. */ class SignatureConfigurationV1 {
  private SignatureConfigurationV1() {}

  /** Returns an instance of the {@code SignatureConfigurationV1}. */
  @InlineMe(
      replacement = "SignatureConfig2026.get()",
      imports = {"com.google.crypto.tink.signature.SignatureConfig2026"}
  )
  public static Configuration get() throws GeneralSecurityException {
    return SignatureConfig2026.get();
  }
}
