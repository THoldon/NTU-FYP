script_location=$(pwd)
./specific_google_chrome.sh #comment out if chromedriver is already installed
rm seed.pcap

#cd /home/ubuntu/FYP/images/for_debug #create a folder to place images in and go there
cd "$1"

for file in *.tar.gz; do
	rm -r ../../extracted_image #create a folder to place extracted image
	mkdir ../../extracted_image
	tar -xvzf "$file" -C ../../extracted_image

	cd ../../extracted_image/*/*/debug
	img_location=$(pwd)
	cd "$script_location"
	./docker_compose.sh "$img_location" "$script_location"
	echo "after docker_compose"
	cd "$1"
done

