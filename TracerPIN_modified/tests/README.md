# TracerPIN regression tests

Run the deterministic interior-pointer tests on a machine with Intel PIN:

```bash
export PIN_ROOT=/path/to/pin-3.30-98830-g1d7b601b3-gcc-linux
./tests/run_regression.sh
```

The suite checks that:

- exact pointers preserve the existing behavior;
- interior pointers remain ignored by default;
- `-interior 1 -interior-size 4` traces the selected section and values;
- an oversized logical section is rejected without crashing.

The script uses a temporary directory for the executable and trace files.
