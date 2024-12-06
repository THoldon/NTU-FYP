echo "$1"
cd "$1"

docker-compose down
docker-compose build
docker-compose up & python3 "$2"/seed_scrape.py "$1" "$2" & pid1=$! #call python script to login and get pcap
wait $pid1
cd "$1"
docker-compose down
docker network prune -f #clear the network bridge
docker image rm debug_gh_rehosted #clear the docker image
