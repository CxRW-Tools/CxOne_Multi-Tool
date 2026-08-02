"""
Operations engines — the long-running work verbs sit behind these modules.

Submodules are imported explicitly by their callers (`from ops.run import
run_scan`, `from ops.realism import RealismModel`, …) rather than re-exported
here, so importing `ops` stays cheap and free of import cycles.
"""
