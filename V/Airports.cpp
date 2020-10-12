#include "../Share/Server.cpp"
#include "../Share/Utility.cpp"
#include <unistd.h>
#include <map>
#include <fstream>
#include <string.h>
#include <iostream>
#include <exception>

void* readMessage(void *sid);
string planeID;
string airport;
char message[] = "Test";

/*************************************************************************
 ** Main Routine
 */

int main(void)
{
    Server server;
    server.StartServer("Airports", readMessage, 2224);
	return(0);
}

string GenerateResponse(string request)
{
    //V, Ticket, E(KeyC_V)[P,TS];
    //decrypt the request
    char rec[1024];
    string eResponse;

    if(request.size() == 1024)
    {
        Utility::PrintMessage(Utility::TGS.c_str(), false, "Recieved Request not valid.", request.c_str());
        return request;
    }

    Utility::PrintMessage(Utility::Airports.c_str(), false, "Recieved Request: %s.", request.c_str());

    //0-V, 1-Ticker, 2-Authp
    vector<string> clientRequest = Utility::Tokenize(request, Utility::msgDelimiters);

    if(clientRequest.size() == 1)
    {
        string dRequest = Utility::AESDecrypt(clientRequest[0], Utility::KeyC_V);

        if(dRequest == "land")
        {
            Utility::PrintMessage(Utility::Airports.c_str(), true, "Recieved landing request from %s. %s"
                    , planeID.c_str(), Utility::GetPrettyTime().c_str());
            sprintf(rec, "%s %s Arrive %s", airport.c_str(), planeID.c_str(), Utility::GetPrettyTime().c_str());
            Utility::WriteRecord(rec);
            Utility::PrintMessage(Utility::Airports.c_str(), true, "Approved landing request from %s. %s"
                    , planeID.c_str(), Utility::GetPrettyTime().c_str());
            eResponse = Utility::AESEncrypt("Recieved Permission to land.", Utility::KeyC_V);
            eResponse.append(Utility::MessageTail);
            return eResponse;
        }
        else if(dRequest == "depart")
        {
            Utility::PrintMessage(Utility::Airports.c_str(), true, "Receieved take-off request from %s. %s"
                    , planeID.c_str(), Utility::GetPrettyTime().c_str());
            sprintf(rec, "%s %s Depart %s", airport.c_str(), planeID.c_str(), Utility::GetPrettyTime().c_str());
            Utility::WriteRecord(rec);
            Utility::PrintMessage(Utility::Airports.c_str(), true, "Approved take-off request from %s. %s"
                    , planeID.c_str(), Utility::GetPrettyTime().c_str());
            eResponse = Utility::AESEncrypt("Recieved Permission to take off.", Utility::KeyC_V);
            eResponse.append(Utility::MessageTail);
            return eResponse;
        }
        else if(dRequest == "quit")
        {
            Utility::PrintMessage(Utility::Airports.c_str(), true, "Connection terminated by %s. %s"
                    , planeID.c_str(), Utility::GetPrettyTime().c_str());
            eResponse = Utility::AESEncrypt("Quit", Utility::KeyC_V);
            eResponse.append(Utility::MessageTail);
            return eResponse;
        }
    }

    string dAuthP;
    string dTicket;
    vector<string> authP;

    try
    {
        Utility::PrintMessage(Utility::Airports.c_str(), false, "AuthP: %s. Size: %i.", clientRequest[2].c_str(), clientRequest[2].size());
        dAuthP = Utility::AESDecrypt(clientRequest[2], Utility::KeyC_V);
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Decrypted AuthP: %s.", dAuthP.c_str());

        //E(KeyC_V)[PlaneID,TimeStamp]
        authP = Utility::Tokenize(dAuthP, Utility::AuthPDelimiters);

        Utility::PrintMessage(Utility::Airports.c_str(), false, "Ticket: %s. Size: %i.", clientRequest[1].c_str(), clientRequest[1].size());
        dTicket = Utility::AESDecrypt(clientRequest[1], Utility::KeyTGS_V);
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Decrypted Ticket: %s.", dTicket.c_str());
    }
    catch(exception& e)
    {
        return Utility::AESModuleError;
    }

    //E(KeyTGS_V)[KeyC_V, PlaneID, V, Timestamp)
    vector<string> ticket = Utility::Tokenize(dTicket, Utility::ticketDelimiters);

    int time = atoi(authP[1].c_str());

    if(Utility::CheckTimeElapsedLimit(time, 60) == true)
    {
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Time Recieved: %s", time);
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Invalid Timestamp.");
        return Utility::TimestampExceeded;
    }

    if(authP[0] != ticket[1])
    {
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Auth Plane: %s", authP[0].c_str());
        Utility::PrintMessage(Utility::Airports.c_str(), false, "Ticket Plane: %s", ticket[1].c_str());
        return Utility::PlaneIDNotValid;
    }

    Utility::PrintMessage(Utility::Airports.c_str(), true, "Ticket checked.");
    Utility::PrintMessage(Utility::Airports.c_str(), true, "Connection established with %s", authP[0].c_str());
    planeID = authP[0];
    airport = ticket[2];

    string response = Utility::BuildProperMsg("%i", time+1);

    eResponse = Utility::AESEncrypt(response, Utility::KeyC_V);

    eResponse.append(Utility::MessageTail);

     Utility::PrintMessage(Utility::Airports.c_str(), true, "Sending Response : %s", eResponse.c_str());

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
