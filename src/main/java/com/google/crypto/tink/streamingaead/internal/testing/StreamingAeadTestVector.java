// Copyright 2024 Google LLC
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

package com.google.crypto.tink.streamingaead.internal.testing;

import com.google.crypto.tink.streamingaead.StreamingAeadKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/** Test vector for StreamingAEAD encryption. */
@Immutable
public final class StreamingAeadTestVector {
  public StreamingAeadTestVector(
      StreamingAeadKey key, byte[] plaintext, byte[] associatedData, byte[] ciphertext) {
    this.key = key;
    this.plaintext = Bytes.copyFrom(plaintext);
    this.associatedData = Bytes.copyFrom(associatedData);
    this.ciphertext = Bytes.copyFrom(ciphertext);
  }

  private final StreamingAeadKey key;
  private final Bytes plaintext;
  private final Bytes associatedData;
  private final Bytes ciphertext;

  public StreamingAeadKey getKey() {
    return key;
  }

  public byte[] getPlaintext() {
    return plaintext.toByteArray();
  }

  public byte[] getAssociatedData() {
    return associatedData.toByteArray();
  }

  public byte[] getCiphertext() {
    return ciphertext.toByteArray();
  }
}
