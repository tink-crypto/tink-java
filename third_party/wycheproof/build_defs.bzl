"""Macro for working with Wycheproof test vectors."""

def _wycheproof_vectors_impl(ctx):
    """Makes vectors in a directory available."""

    all_input_files = [f for f in ctx.files.srcs]
    all_outputs = []
    for f in all_input_files:
        out_path = f.basename
        if ctx.attr.outdir:
            out_path = "{}/{}".format(ctx.attr.outdir, f.basename)
        out = ctx.actions.declare_file(out_path)
        all_outputs.append(out)
        ctx.actions.symlink(
            output = out,
            target_file = f,
        )
    return [
        DefaultInfo(
            files = depset(all_outputs),
            runfiles = ctx.runfiles(files = all_outputs),
        ),
    ]

wycheproof_vectors = rule(
    implementation = _wycheproof_vectors_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "outdir": attr.string(),
    },
)
