"""Returns the module version defined in MODULE.bazel."""

def get_module_version(name):
    # We need a name by convention (this is a macro, and hence needs a name)
    return native.module_version()
