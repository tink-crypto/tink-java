# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tink Java Bazel Module extensions."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _wycheproof_impl(_ctx):
    # Commit from 2025-09-01.
    # Corresponds to wycheproof-v0-vectors tag.
    http_archive(
        name = "wycheproof",
        strip_prefix = "wycheproof-b51abcfb8dafa5316791e57cf48512a2147d9671",
        url = "https://github.com/c2sp/wycheproof/archive/b51abcfb8dafa5316791e57cf48512a2147d9671.zip",
        sha256 = "56ba9f3deba06b1cc33430a770a9b6bd6ddc8af69188ea0b46d10bda60176978",
        build_file = "@//testvectors:wycheproof.BUILD.bazel",
    )

wycheproof_extension = module_extension(
    implementation = _wycheproof_impl,
)
