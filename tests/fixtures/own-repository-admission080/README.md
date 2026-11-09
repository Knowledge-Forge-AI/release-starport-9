# Proposed 0.8 paired-consumer body fixture

The `consumer/` files are the exact nine proposed 0.8 paired-P bodies whose
SHA-256 values are fixed in `CONSUMER_FILE_HASHES_080` in
`src/rs9/own_repository_admission080.py`. They are source-authority fixtures, not a live checkout and not
publication or qualification evidence.

Tests construct the descriptor, source commit/tree, API responses, original-run
configuration, and physical temporary checkout independently. Those synthetic
Git/API/run values are test fixtures only; this directory does not mint an
original run, native receipt, signing authority, or publication authority.
