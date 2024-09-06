echo "$1"
cd "$1"

docker-compose down
docker-compose build
docker-compose up & python3 "$2"/seed_scrape.py "$1" & pid1=$! #call python script to do html stuff then call another script to docker-compose down
wait $pid1
docker-compose down
