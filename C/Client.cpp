#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include "../Share/Utility.cpp"
#include <string.h>
#include <exception>

#define	LENGTH	1024
#pragma GCC diagnostic warning "-Wformat"

const string host = "127.0.0.1";
const int ASPort = 2222;
const int TGSPort = 2223;
const int VPort = 2224;
map<string, string> keyCAS;

string SendRequest(string request, string host, int port)
{
	char	iobuf[LENGTH];
	struct	sockaddr_in server_sockaddr;
	int	s, rc, nread;

	if (host.empty())
	{
		printf("usage: %s <server_address>\r\n", host.c_str());
		exit(1);
	}

	server_sockaddr.sin_addr.s_addr = inet_addr(host.c_str());
	if (server_sockaddr.sin_addr.s_addr == -1)
	{
		printf("%s is a malformed address\r\n",  host.c_str());
		exit(1);
	}

	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port   = htons(port);

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1)
	{
		perror("socket");
		exit(1);
	}

	rc = connect(s, (struct sockaddr *) & server_sockaddr, sizeof (server_sockaddr));
	if (rc == -1)
	{
		perror("connect");
		exit(1);
	}
	//printf("\nconnection has been set\n");

	/*
	* Assumes that the TCP quotas add up to more than 1024 bytes.
	* Otherwise this strategy invites deadlock.
	*/
	memset(iobuf, '\0', LENGTH);

    rc = write(s, request.c_str(), request.size());
	if (rc == -1)
	{
		perror("write");
		exit(1);
	}
	//printf("\r\n %d bytes written ...", rc);

	/*
	* read() does not necessarily return the full amount requested, so
	* repeat the operation if necessary.
	*/
	rc = read(s, iobuf, sizeof(iobuf));
	if (rc == -1)
	{
		perror("read");
		exit(1);
	}
	//printf("\r\n %d bytes read ...", rc);
	//printf("\nReceive response:\n %s", iobuf);
	//printf("\n");

	string response = Utility::BuildStringFromBuffer(iobuf);

	rc = close(s);

	//printf("\r\nSocket Closed,  return code=%04lx", (long unsigned int)rc);

	if (rc == -1)
	{
		perror("close");
		exit(1);
	}

	return response;
}

void ListPlanes()
{
    //load the keyCAS.txt
    vector<string> planes = Utility::GetObjectListFromFile("keyCAS.txt");
    if(planes.empty())
    {
        planes = Utility::GetObjectListFromFile("C/keyCAS.txt");
    }

    for(vector<string>::iterator iter = planes.begin(); iter != planes.end(); ++iter)
    {
        cout << (*iter).c_str() << endl;
    }
}

bool CheckPlaneIDValid(string planeID)
{
    vector<string> planes = Utility::GetObjectListFromFile("keyCAS.txt");
    if(planes.empty())
    {
        planes = Utility::GetObjectListFromFile("C/keyCAS.txt");
    }

    return Utility::CheckVectorContains(planes,planeID);
}

void ListAirports()
{
    //load the access.txt
    vector<string> airports = Utility::GetAirportsFromFile("access.txt");
    if(airports.empty())
    {
        airports = Utility::GetAirportsFromFile("C/access.txt");
    }

    for(vector<string>::iterator iter = airports.begin(); iter != airports.end(); ++iter)
    {
        cout << (*iter).c_str() << endl;
    }

}

vector<string> ContactAS(string planeID)
{
    //Contact AS with the following information: PlaneID, TGS, Timestamp
    //Build request
    string request = Utility::BuildProperMsg("%s,%s,%i", planeID.c_str(), Utility::TGS.c_str(), Utility::GetCurrentTime());
    request.append(Utility::MessageTail);

    Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting AS...");

    string incomingResponse = SendRequest(request, host, ASPort);

    while(incomingResponse.size() == 1024)
    {
        Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting PIG again..");
        incomingResponse = SendRequest(request, host, ASPort);
    }

    Utility::PrintMessage(Utility::Client.c_str(), false, "Response from AS: %s", incomingResponse.c_str());

    string dIncomingResponse = Utility::AESDecrypt(incomingResponse, keyCAS[planeID]);

    Utility::PrintMessage(Utility::Client.c_str(), false, "Decrypted Response from AS: %s", dIncomingResponse.c_str());

    vector<string> response = Utility::Tokenize(dIncomingResponse, Utility::msgDelimiters);

    return response;
}

string BuildAuthP(string planeID, string airport)
{
    //E(KeyC_TGS)(PlaneID, Timestamp, V)
    string authp = Utility::BuildProperAuthP("%s,%i,%s", planeID.c_str(), Utility::GetCurrentTime(), airport.c_str());

    string eAuthp = Utility::AESEncrypt(authp, Utility::KeyC_TGS);

    return eAuthp;
}

string ContactAirport(string planeID, string airport, string ticket, int time)
{
    //V, Ticket, E(KeyC_V)[P,TS];
    string authp = Utility::BuildProperAuthP("%s,%i", planeID.c_str(), time);

    string eAuthP = Utility::AESEncrypt(authp, Utility::KeyC_V);

    string request = Utility::BuildProperMsg("%s,%s,%s", airport.c_str(), ticket.c_str(), eAuthP.c_str());

    request.append(Utility::MessageTail);

    Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting %s airport..", airport.c_str());

    string response = SendRequest(request, host, VPort);

    Utility::PrintMessage(Utility::Client.c_str(), false, "string empty %B", response.empty());

    while(response.size() == 1024)
    {
        Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting %s airport again..", airport.c_str());
        response = SendRequest(request, host, VPort);
    }

    Utility::PrintMessage(Utility::Client.c_str(), false, "Airport Response : %s", response.c_str());

    string dResponse = Utility::AESDecrypt(response, Utility::KeyC_V);

    Utility::PrintMessage(Utility::Client.c_str(), false, "Decrypted Airport Response : %s", dResponse.c_str());

    return dResponse;
}

vector<string> ContactTGS(string planeID, string airport, string ticket)
{
    //Contact TGS
    //V,Ticket, E(KeyC_TGS)(PlaneID, Timestamp, V)

    string request = Utility::BuildProperMsg("%s,%s,%s", airport.c_str(), ticket.c_str(), BuildAuthP(planeID, airport).c_str());

    request.append(Utility::MessageTail);

    Utility::PrintMessage(Utility::Client.c_str(), false, "Contacting TGS : %s", request.c_str());

    Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting TGS...");

    string incomingResponse = SendRequest(request, host, TGSPort);

    while(incomingResponse.size() == 1024)
    {
        Utility::PrintMessage(Utility::Client.c_str(), true, "Contacting TGS again..");
        incomingResponse = SendRequest(request, host, TGSPort);
    }

    Utility::PrintMessage(Utility::Client.c_str(), false, "Response from TGS: %s", incomingResponse.c_str());
    //decrypt the response witk KC_TGS

    string dIncomingResponse = Utility::AESDecrypt(incomingResponse, Utility::KeyC_TGS);

    vector<string> response = Utility::Tokenize(dIncomingResponse, Utility::msgDelimiters);

    return response;
}

Result CheckASResponse(vector<string> asResponse)
{
    Result res;
    //E(KeyC_AS)[KeyC_TGS, PlaneID, TGS, Timestamp, Ticket]
    //check timestamp
    if(Utility::CheckTimeElapsedLimit(atoi(asResponse[3].c_str()), 60) == true)
    {
        res.obj = "Invalid Timestamp";
        res.passed = false;
        return res;
    }

    //return the ticket.
    res.obj = asResponse[4];
    res.passed = true;
    return res;
}

Result CheckTGSResponse(vector<string> tgsResponse)
{
    Result res;
    //E(KeyC_TGS)[KeyC_V, PlaneID, Timestamp, Timestamp+1, Ticket]
    //check timestamp
    if(Utility::CheckTimeElapsedLimit(atoi(tgsResponse[2].c_str()), 60) == true)
    {
        res.obj = "Invalid Timestamp";
        res.passed = false;
        return res;
    }

    //check TS3
    if((atoi(tgsResponse[3].c_str()) - atoi(tgsResponse[2].c_str())) != 1)
    {
        res.obj = "Invalid Timestamp 2";
        res.passed = false;
        return res;
    }

    //return the ticket.
    res.obj = tgsResponse[4];
    res.passed = true;
    return res;
}

void PrintHelp()
{
    cout << "Invalid option. Usage: client planeID airport" << endl;
    cout << "Usage: client listplanes (List the planes that you can use)" << endl;
    cout << "Usage: client listports (List the airports that you can use)" << endl;
}

void PrintAirportCMD(string planeID)
{
    printf("> %s: %s: ", Utility::Client.c_str(), planeID.c_str());
}

void StartCommunicationWithAirport(string planeID)
{
    for(;;)
    {
        PrintAirportCMD(planeID);
        string response;
        string vRequest;
        string dResponse;
        string request;
        cin >> request;

        if(request == "land")
        {
            vRequest = Utility::AESEncrypt("land", Utility::KeyC_V);
            vRequest.append(Utility::MessageTail);
            response = SendRequest(vRequest, host, VPort);
            dResponse = Utility::AESDecrypt(response, Utility::KeyC_V);
            Utility::PrintMessage(Utility::Client.c_str(), true, "%s", dResponse.c_str());
        }
        else if(request == "depart")
        {
            vRequest = Utility::AESEncrypt("depart", Utility::KeyC_V);
            vRequest.append(Utility::MessageTail);
            response = SendRequest(vRequest, host, VPort);
            dResponse = Utility::AESDecrypt(response, Utility::KeyC_V);
            Utility::PrintMessage(Utility::Client.c_str(), true, "%s", dResponse.c_str());
        }
        else if(request == "quit")
        {
            Utility::PrintMessage(Utility::Client.c_str(), true, "QUIT");
            vRequest = Utility::AESEncrypt("quit", Utility::KeyC_V);
            vRequest.append(Utility::MessageTail);
            response = SendRequest(vRequest, host, VPort);
            dResponse = Utility::AESDecrypt(response, Utility::KeyC_V);
            break;
        }
        else
        {
            Utility::PrintMessage(Utility::Client.c_str(), true, "Unknown Request.");
        }
    }
}

int main(int argc, char **argv)
{
    //load the keyCAS.txt
    keyCAS = Utility::GetMapFromFile("keyCAS.txt");
    if(keyCAS.empty())
    {
        Utility::PrintMessage(Utility::Client.c_str(), false, "Trying alternate path for KeyCAS.");
        keyCAS = Utility::GetMapFromFile("C/keyCAS.txt");
    }

    string planeID;
    string airport;

    if(argc == 1)
	{
		PrintHelp();
	}
    else if(strcmp(argv[1],"listplanes") == 0)
    {
		ListPlanes();
	}
	else if(strcmp(argv[1],"listports") == 0)
	{
		ListAirports();
	}
	else if(argc == 3)
	{
	    try
	    {
	    if(!CheckPlaneIDValid(argv[1]))
	    {
	        Utility::PrintMessage(Utility::Client.c_str(), true, "%s is not a valid plane.", argv[1]);
	        return 0;
	    }

        planeID = argv[1];
        airport = argv[2];
        //Contact AS
	    vector<string> ASResponse = ContactAS(planeID);

	    if(ASResponse.size() < 5)
	    {
	        //not valid response, print last message
	        Utility::PrintMessage(Utility::Client.c_str(), true, ASResponse[0].c_str());

	        return 0;
	    }

        //Validate AS Response
	    Result ticket_TGS = CheckASResponse(ASResponse);
	    //E(KeyAS_TGS)[KeyC_TGS, PlaneID, TGS, Timestamp]
	    if(ticket_TGS.passed != true )
	    {
            //not valid response, print last message
	        Utility::PrintMessage(Utility::Client.c_str(), true, "AS Response is not valid : %s", ticket_TGS.obj.c_str());

	        return 0;
	    }

	    //Response is valid
        Utility::PrintMessage(Utility::Client.c_str(), true, "Got a TGS ticket...");
        //send ticket to AGS
        Utility::PrintMessage(Utility::Client.c_str(), false, "Ticket: %s", ticket_TGS.obj.c_str());
        vector<string> TGSResponse = ContactTGS(planeID, airport, ticket_TGS.obj);

        if(TGSResponse.size() < 5)
        {
            //not valid response, print last message
	        Utility::PrintMessage(Utility::Client.c_str(), true, TGSResponse[0].c_str());

	        return 0;
        }

        //Validate TGS Response
	    Result validateTGS = CheckTGSResponse(TGSResponse);
        if(validateTGS.passed != true )
	    {
            //not valid response, print last message
	        Utility::PrintMessage(Utility::Client.c_str(), true, "TGS Response is not valid : %s", validateTGS.obj.c_str());

	        return 0;
	    }

	    //Response is valid
        Utility::PrintMessage(Utility::Client.c_str(), true, "Got a airport ticket...");
        Utility::PrintMessage(Utility::Client.c_str(), false, "Ticket: %s", validateTGS.obj.c_str());
        //Contact Airport!!!

        int time = Utility::GetCurrentTime();
        string airportReply = ContactAirport(planeID, airport, validateTGS.obj.c_str(), time);

        //check airport reply
        int vResponse = atoi(airportReply.c_str());

        if(time+1 != vResponse)
        {
            Utility::PrintMessage(Utility::Client.c_str(), true, "Airport response not valid");

            return 0;
        }

        Utility::PrintMessage(Utility::Client.c_str(), true, "Connected!");

        StartCommunicationWithAirport(planeID);
	    }
	    catch(exception& e)
	    {
	        Utility::PrintMessage(Utility::Client.c_str(), true, "Error. Please try again.");
	    }

	}else
	{
	    PrintHelp();
	}
	return 0;
}
