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

package com.google.crypto.tink.internal;

/** ASN.1 tag and value constants. */
public final class Asn1TagConstants {
  public static final byte TAG_INTEGER = 0x02;
  public static final byte TAG_BIT_STRING = 0x03;
  public static final byte TAG_OCTET_STRING = 0x04;
  public static final byte TAG_NULL = 0x05;
  public static final byte TAG_OBJECT_IDENTIFIER = 0x06;
  public static final byte TAG_SEQUENCE = 0x30;
  public static final byte NULL_BYTE = 0x00;

  private Asn1TagConstants() {}
}
