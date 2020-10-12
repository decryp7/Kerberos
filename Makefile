all : client pig auru airports run

client : C/Client.cpp Share/Utility.cpp
	@echo "Building Client"
	@g++ C/Client.cpp -o C/client -L ./Share/cryptopp -lcryptopp

pig : AS/PIG.cpp Share/Server.cpp
	@echo "Building (Plane Identification Group)"
	@g++ AS/PIG.cpp -o AS/PIG -lpthread -L ./Share/cryptopp -lcryptopp

auru : TGS/AURU.cpp Share/Server.cpp
	@echo "Building AURU(Airspace Authorisation Authority)"
	@g++ TGS/AURU.cpp -o TGS/AURU -lpthread -L ./Share/cryptopp -lcryptopp

airports : V/Airports.cpp Share/Server.cpp
	@echo "Building Airports"
	@g++ V/Airports.cpp -o V/airports -lpthread -L ./Share/cryptopp -lcryptopp

run: 
	@echo Starting Servers
	@xterm & xterm -e AS/PIG & xterm -e TGS/AURU & xterm -e V/airports
