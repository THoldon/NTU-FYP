/custom_mutator contains some shared objects needed for the custom mutator and the custom mutator's shared object

/seeds should contain the seeds from the seed_scraper

fuzz.sh.j2 in /templates has been slightly edited to support the custom mutator. export AFL_CUSTOM_MUTATOR_ONLY=1 can be commented or uncommented depending on the use.
