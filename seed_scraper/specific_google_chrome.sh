#sudo wget https://mirror.cs.uchicago.edu/google-chrome/pool/main/g/google-chrome-stable/google-chrome-stable_99.0.4844.84-1_amd64.deb && \ #comment out if chromedriver downloaded
sudo dpkg -i google-chrome-stable_99.0.4844.84-1_amd64.deb && \
sudo apt-mark hold google-chrome-stable && \
google-chrome-stable --version \
