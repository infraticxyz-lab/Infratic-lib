# Feature tests

One file per feature, compiled into `../test_main.cpp` by `../build.sh`:

```cpp
INFRATIC_TEST(feature_name)
{
    // `sol` is an Infratic on https://mock.rpc, `vec` is ../vectors_feature_name.json
    CHECK(..., "what is checked");
}
```

Reference values come from `../js/gen_feature_name.mjs` (run with node, writes
`../vectors_feature_name.json`). Generate them with the official JS libraries
(@solana/web3.js, @solana/spl-token, ...) and a seeded PRNG of the file's own,
so the output never changes between runs.
