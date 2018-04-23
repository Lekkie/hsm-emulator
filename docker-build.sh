rm -f ./docker/hsmsim-akka*.jar
mvn install
cp ./hsmsim-akka/target/hsmsim-akka-0.0.1-SNAPSHOT-jar-with-dependencies.jar ./docker/
docker rm $(docker ps -a -q)
docker rmi -f hsm-emulator

# docker hub username
USERNAME=lekkie
# image name
IMAGE=hsm-emulator

version=`cat ./docker/VERSION`
version="${version%.*}.$((${version##*.}+1))"
echo $version > './docker/VERSION'
echo "version: $version"

docker build -t $USERNAME/$IMAGE ./docker/

docker tag $USERNAME/$IMAGE $USERNAME/$IMAGE:$version



#docker run -it -p 1501:1501 hsm-simulator