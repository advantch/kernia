# kernia-cli

Command-line tools for Kernia: scaffold a project, generate and apply database migrations, and manage secrets.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-cli

## Usage

```bash
kernia init --adapter sqlite --framework fastapi   # writes auth.py + .env.example
kernia secret                                      # generate a KERNIA_SECRET
kernia generate                                    # emit a database migration
kernia migrate                                     # apply it
kernia info                                         # print resolved config
```

Run `kernia --help` for the full command tree.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
