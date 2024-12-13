#sudo wget https://mirror.cs.uchicago.edu/google-chrome/pool/main/g/google-chrome-stable/google-chrome-stable_99.0.4844.84-1_amd64.deb && \
#sudo dpkg -i google-chrome-stable_99.0.4844.84-1_amd64.deb && \
#sudo apt-mark hold google-chrome-stable && \
#google-chrome-stable --version \
#sudo apt-get --only-upgrade install google-chrome-stable && \
#comment out first line if chrome downloaded (needs 99.0 chromedriver)

#sudo wget https://mirror.cs.uchicago.edu/google-chrome/pool/main/g/google-chrome-stable/google-chrome-stable_128.0.6613.119-1_amd64.deb && \
sudo dpkg -i google-chrome-stable_128.0.6613.119-1_amd64.deb && \
sudo apt-mark hold google-chrome-stable && \
google-chrome-stable --version
#comment out first line if chrome downloaded (needs 128.0 chromedriver)
