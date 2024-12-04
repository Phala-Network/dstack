# dstack-sdk

The DStack SDK for Python.


# For Development

We use [PDM](https://pdm-project.org/en/latest/) for local development and creating an isolated environment.

Just run the following command to initiate development:


```bash
pdm install -d
```

Running test cases with local simulator via `/tmp/tappd.sock`:

```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock pdm run pytest
```
