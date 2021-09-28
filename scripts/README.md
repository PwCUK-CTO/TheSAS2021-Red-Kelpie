Custom ChaCha20 implementation using PyCryptodome to allow for a custom counter to be set.

This works by feeding in `n` blocks of null bytes, to indirectly increment the counter to the desired value.
