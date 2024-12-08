# NTU-FYP 24/25 Solving Real World Vulnerabilities

## Purpose of folders
afl_custom_mutator: Contains source code and compiled binary of the html_mutator and html_mutator_standalone, a standalone version of the mutator for testing. Also a sample_post pcap for testing.

gh3fuzz: Greenhouse fuzzer from [[here](https://github.com/sefcom/gh3fuzz)].

results: Results acquired from some testing.

seed_scraper: Python code to get some POST HTML seeds for use in gh3fuzz

## How to use
1) Make sure there's at least two directories before this folder (can probably edit tar_loop.sh L8-L12 to change this)
2) Run ./tar_loop.sh [folder with .tar.gz in it]
3) Let it run, up to 5 seeds (named seed1,seed2,...,seed5) will be in /seed_scraper
4) Copy these to gh3fuzz/fuzz_bins/seeds
5) Follow instructions in firmware_fuzz to fuzz post-authentication states
6) Run gh3fuzz
