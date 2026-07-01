# kernia-passkey

WebAuthn/FIDO2 passkey plugin for Kernia. Adds passkey registration and authentication with a real WebAuthn verifier. Kept as a standalone package so the `webauthn` dependency stays opt-in.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-passkey

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_passkey import passkey

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[
            email_and_password(),
            passkey(rp_id="example.com", rp_name="Example", origin="https://example.com"),
        ],
    )
)
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
