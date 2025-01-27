# afl_custom_mutator
### Use
The custom mutator, which mutates uneeded fields for a successful request to the firmware
### Explanation of some files
http_mutator_standalone.c is the standalone version of the http_mutator that can be used for testing,edit main accordingly to what you need. **To compile:** gcc http_mutator_standalone.c -g [location of AFLplusplus/src/afl-performance.c] -I [location of AFLplusplus/include] -o http_mutator_standalone **To use:** ./http_mutator_standalone [location of seed to test]

http_mutator.c can be created with: cp http_mutator_standalone.c http_mutator.c, then commenting out the dummy variables in afl_custom_init (4 lines after comment about dummy variables) and main. **To compile:** gcc -fPIC -O3 -I [location of AFLplusplus/include] -I. -shared -o http_mutator.so http_mutator.c [location of AFLplusplus/src/afl-performance.c]. http_mutator.so is to be placed in gh3fuzz/fuzz_bins/custom_mutator.

sample_post has some sample POST HTTP requests that can be used for testing.
