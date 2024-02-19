CFLAGS = -Wall -Werror -std=c++17

all: main/main.cpp
	g++ $(CFLAGS) -o fileserver main/main.cpp

clean:
	rm -rf fileserver

build-docker:
	docker build -t bibifi .

run-docker:
	docker run -it bibifi
