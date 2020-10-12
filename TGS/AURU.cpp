#include "../Share/Server.cpp"
#include "../Share/Utility.cpp"
#include <unistd.h>
#include <map>
#include <fstream>
#include <string.h>
#include <exception>

void* readMessage(void *sid);

char message[] = "Test";

/*************************************************************************
 ** Main Routine
 */
int main(void)
{
    Server server;
    server.StartServer("AURA(Airspace Authorisation Authority)", readMessage, 2223);
	return(0);
}

bool CheckPlaneIDValid(string planeID)
{
    vector<string> planes = Utility::GetObjectListFromFile("access.txt");
    if(planes.empty())
    {
        planes = Utility::GetObjectListFromFile("TGS/access.txt");
    }

    return Utility::CheckVectorContains(planes,planeID);
}

bool CheckPlaneAirport(string planeID, string airport)
{
    map<string, string> planeAirport = Utility::GetMapFromFile("access.txt");
    if(planeAirport.empty())
    {
        planeAirport = Utility::GetMapFromFile("TGS/access.txt");
    }

    vector<string> airports = Utility::Tokenize(planeAirport[planeID], ",");

    return Utility::CheckVectorContains(airports, airport);
}

string GenerateTicket(string planeID, string airport, int time)
{
    Utility::PrintMessage(Utility::TGS.c_str(), false, "Recieved request to generate ticket");
    //E(KeyTGS,V)[KeyC_V, PlaneID, V, Timestamp]
    string ticket = Utility::BuildProperTicket("%s,%s,%s,%i", Utility::KeyC_V.c_str()
                        , planeID.c_str(), airport.c_str(), time);

    //encryption
    string eTicket = Utility::AESEncrypt(ticket, Utility::KeyTGS_V);

    return eTicket;
}

string GenerateResponse(string request)
{
    //decrypt the request

    if(request.size() == 1024)
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Recieved Request not valid.", request.c_str());
        return request;
    }

    Utility::PrintMessage(Utility::TGS.c_str(), false, "Recieved Request: %s.", request.c_str());

    //0-V, 1-Ticker, 2-Authp
    vector<string> clientRequest = Utility::Tokenize(request, Utility::msgDelimiters);

    if(clientRequest.size() < 3)
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Invalid Request.");
        return Utility::InvalidRequest;
    }

    Utility::PrintMessage(Utility::TGS.c_str(), false, "Request is valid.");

    string dAuthP;

    try
    {
        dAuthP = Utility::AESDecrypt(clientRequest[2], Utility::KeyC_TGS);
    }
    catch(exception& e)
    {
        return Utility::AESModuleError;
    }

    //Authp 0-PlaneID, 1-Timestamp, 2-V
    vector<string> authP = Utility::Tokenize(dAuthP, Utility::AuthPDelimiters);

    if(CheckPlaneAirport(authP[0], authP[2]) == false)
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Invalid Airport Request.");
        return Utility::InvalidAirportRequest;
    }

    //check planeID
    if(!CheckPlaneIDValid(authP[0]))
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Invalid Plane ID.");
        return Utility::PlaneIDNotValid;
    }


    //check timestamp
    if(Utility::CheckTimeElapsedLimit(atoi(authP[1].c_str()), 60) == true)
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Time Recieved: %s", authP[1].c_str());
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Invalid Timestamp.");
        return Utility::TimestampExceeded;
    }

    int time  = Utility::GetCurrentTime();

    //E(KeyC_TGS)[KeyC_V, V, Timestamp, Timestamp+1, Ticket]
    string response = Utility::BuildProperMsg("%s,%s,%i,%i,%s", Utility::KeyC_V.c_str(), authP[2].c_str()
                        , time, time+1, GenerateTicket(authP[0], authP[2], time).c_str());

    string eResponse = Utility::AESEncrypt(response, Utility::KeyC_TGS);

    eResponse.append(Utility::MessageTail);

    Utility::PrintMessage(Utility::TGS.c_str(), false, "Sending response: %s", eResponse.c_str());

    return eResponse;
}

/*
 * The daughter thread deletes the socket before exiting.
 */
void* readMessage(void *sid)
{
	int    s = *((int*)sid);
	int    rc;
	char   iobuf[LENGTH];

	while(rc = read(s, iobuf, sizeof (iobuf)))
	{
		if (rc == -1)
		{
			perror("read");
			close(s);
			pthread_exit(0);
		}

		string request = Utility::BuildStringFromBuffer(iobuf);
        string response = GenerateResponse(request);

		rc = write(s, response.c_str(), response.size());

        memset(iobuf, '\0', LENGTH);

		if (rc == -1)
		{
			perror("write");
			close(s);
			pthread_exit(0);
		}

	}
	close(s);
	pthread_exit(0);
    return 0;
}
