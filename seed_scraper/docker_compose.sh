cd /home/ubuntu/FYP/images/rehosted_img_aug

for file in *.tar.gz; do
	rm -r ../../extracted_image
	mkdir ../../extracted_image
	tar -xvzf "$file" -C ../../extracted_image

	cd ../../extracted_image/*/*/debug
	docker-compose down
	docker-compose build
	docker-compose up
	docker-compose down
	#docker network prune
	#docker builder prune
	cd /home/ubuntu/FYP/images/rehosted_img_aug
done

