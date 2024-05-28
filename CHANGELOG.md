23.07.2022
* Replace macro for inlined functions, up to 10% increase in performance for the
  default benchmarks.

05.07.2022

* Pulling apart code encode/decode into main kernel.
* Separating the code into an `unsigned` crate where 
  we defined the `Unsigned` trait.
* Adding performance test through `test::bencher` (nightly rust)

27.06.2022

* Fixing error in `expand_key` (key expansion algorithm)
* Adding test from
  https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html#rfc.section.4
  to support u8, u16, u64, u128
* Adding one extra field (BITESU32) to support generic vector length on
 `key_expand`

