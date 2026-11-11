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
    # Commit from 2026-10-23.
    http_archive(
        name = "wycheproof",
        strip_prefix = "wycheproof-d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9",
        url = "https://github.com/c2sp/wycheproof/archive/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9.zip",
        sha256 = "8561d5afddd7ecbf92591f81f8b45da921e0444d7c2cc2fc84412802a7450ada",
        build_file = "@//third_party/wycheproof:wycheproof.BUILD.bazel",
    )

wycheproof_extension = module_extension(
    implementation = _wycheproof_impl,
)
