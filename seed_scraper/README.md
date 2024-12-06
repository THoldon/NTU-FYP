# seed_scraper
### Use
Scrapes the firmware for POST HTML requests, to be used as seeds for fuzzing.
### Explanation of some files
specific_google_chrome.sh installs (and downloads in the first line) a specific google chrome version to be used in the Python programs.

tar_loop.sh extracts the .tar.gz in a folder one by one and runs docker_compose.sh. **To use:** ./tar_loop.sh [location of folder containing .tar.gz].

Initializer.py is taken from [[here](https://github.com/sefcom/greenhouse/blob/829cbabbb5de64e251dc7f9c2692b2ca39e29b3b/Greenhouse/plugins/Initializer.py)], with some new functions (find_post and click_buttons). Its used to click through the firmware website to gather POST requests.

seed_scrape.py is called from tar_loop.sh and calls Initializer.py, creating seed.pcap. After which it uses extract_post() to find if any POST requests were sniffed and creates up to 5 seeds in the folder
