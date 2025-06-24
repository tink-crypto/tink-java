// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.util.Bytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/** Implements chunked MAC verification from chunked MAC computation. */
final class ChunkedMacVerificationFromComputation implements ChunkedMacVerification {
  private final Bytes tag;
  private final ChunkedMacComputation macComputation;

  private ChunkedMacVerificationFromComputation(ChunkedMacComputation macComputation, byte[] tag) {
    // Checks regarding tag and key sizes, as well as FIPS-compatibility
    // need to be performed by the caller.
    this.macComputation = macComputation;
    this.tag = Bytes.copyFrom(tag);
  }

  @Override
  public void update(ByteBuffer data) throws GeneralSecurityException {
    macComputation.update(data);
  }

  @Override
  public void verifyMac() throws GeneralSecurityException {
    byte[] other = macComputation.computeMac();
    if (!tag.equals(Bytes.copyFrom(other))) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }

  static ChunkedMacVerification create(ChunkedMacComputation macComputation, byte[] tag) {
    return new ChunkedMacVerificationFromComputation(macComputation, tag);
  }
}
