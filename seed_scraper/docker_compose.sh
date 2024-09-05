echo "$1"
cd "$1"

docker-compose down
docker-compose build
docker-compose up #call python script to do html stuff then call another script to docker-compose down
docker-compose down
