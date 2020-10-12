#include "../Share/Server.cpp"
#include "../Share/Utility.cpp"
#include <unistd.h>
#include <map>
#include <fstream>
#include <string.h>

void* readMessage(void *sid);
map<string, string> keyCAS;
char message[] = "Test";

/*************************************************************************
 ** Main Routine
 */
int main(void)
{
    //load the keyCAS.txt
    keyCAS = Utility::GetMapFromFile("keyCAS.txt");
    if(keyCAS.empty())
    {
        Utility::PrintMessage(Utility::PIG.c_str(), false, "Trying alternate path for KeyCAS.");
        keyCAS = Utility::GetMapFromFile("AS/keyCAS.txt");
    }
    //Print the map
    //Utility::PrintMap(keyCAS, "Plane", "Key");
    Server server;
    server.StartServer("PIG(Plane Identification Group)", readMessage, 2222);
	return(0);
}

bool CheckPlaneIDValid(string planeID)
{
    vector<string> planes = Utility::GetObjectListFromFile("keyCAS.txt");
    if(planes.empty())
    {
        planes = Utility::GetObjectListFromFile("AS/keyCAS.txt");
    }

    return Utility::CheckVectorContains(planes,planeID);
}

string GenerateTicket(string planeID)
{
    Utility::PrintMessage(Utility::PIG.c_str(), false, "Recieved request to generate ticket");
    //E(KeyAS_TGS)[KeyC_TGS, PlaneID, TGS, Timestamp]
    string ticket = Utility::BuildProperTicket("%s,%s,%s,%i", Utility::KeyC_TGS.c_str()
                        , planeID.c_str(), Utility::TGS.c_str(), Utility::GetCurrentTime());

    return ticket;
}

string GenerateResponse(string request)
{
    Utility::PrintMessage(Utility::PIG.c_str(), false, "Recieved Request: %s.", request.c_str());

    vector<string> clientRequest = Utility::Tokenize(request, Utility::msgDelimiters);

    Utility::PrintMessage(Utility::PIG.c_str(), false, clientRequest[1].c_str());

    //0-planeID, 1-TGS, 2-TimeStamp
    if(clientRequest.size() < 3)
    {
        Utility::PrintMessage(Utility::PIG.c_str(), false, "Invalid Request.");
        return Utility::InvalidRequest;
    }

    //check planeID
    if(!CheckPlaneIDValid(clientRequest[0]))
    {
        Utility::PrintMessage(Utility::PIG.c_str(), false, "Invalid Plane ID.");
        return Utility::PlaneIDNotValid;
    }

    //check timestamp
    if(Utility::CheckTimeElapsedLimit(atoi(clientRequest[2].c_str()), 60) == true)
    {
        Utility::PrintMessage(Utility::PIG.c_str(), false, "Invalid Timestamp.");
        return Utility::TimestampExceeded;
    }

    //E(KeyC_AS)[KeyC_TGS, PlaneID, TGS, Timestamp, Ticket]
    string response = Utility::BuildProperMsg("%s,%s,%s,%i,%s", Utility::KeyC_TGS.c_str(), clientRequest[0].c_str()
                        , Utility::AURU.c_str(), Utility::GetCurrentTime(), GenerateTicket(clientRequest[0]).c_str());

    Utility::PrintMessage(Utility::PIG.c_str(), false, response.c_str());

    string eResponse = Utility::AESEncrypt(response, keyCAS[clientRequest[0]]);

    eResponse.append(Utility::MessageTail);

    Utility::PrintMessage(Utility::PIG.c_str(), false, "Sending Response : %s", eResponse.c_str());

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
