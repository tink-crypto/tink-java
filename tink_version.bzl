"""Returns the current Tink version defined in MODULE.bazel or "HEAD"."""

def get_tink_version_label(name):
    # We need a name by convention (this is a macro, and hence needs a name)
    result = native.module_version()
    if result != "":
        return result
    return "HEAD"
