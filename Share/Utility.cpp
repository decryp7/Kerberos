#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <iomanip>

// Crypto++
#include "./cryptopp/cryptlib.h"
#include "./cryptopp/aes.h"        // AES
#include "./cryptopp/modes.h"      // CBC_Mode< >
#include "./cryptopp/filters.h"    // StringSource


using namespace std;

struct Result
{
    bool passed;
    string obj;
};

class Utility
{
    public:
        // spilt string into small sections with delimiters
        static vector<string> Tokenize(const string& str, const string& delimiters = " ");
        // get a map of the objects with its associated keys from a file
        static map<string, string> GetMapFromFile(const char * filePath);
        // get object from file
        static vector<string> GetObjectListFromFile(const char * filePath);
        // get list of airports
        static vector<string> GetAirportsFromFile(const char * filePath);
        // check whether vector contains the value
        static bool CheckVectorContains(vector<string> input, string value);
        // output the map to the console
        static void PrintMap(map<string,string> inMap, string left, string right);
        // write to record
        static void WriteRecord(const char* record);
        //get current time
        static int GetCurrentTime();
        static string GetPrettyTime();
        //print message according to debug flag
        static void PrintMessage(string label, bool show, const char* msg, ...);
        //check time elapsed does not break the limit in seconds
        static bool CheckTimeElapsedLimit(int timeStamp, int limit);
        // replace all
        static string ReplaceAll(string& context, const string from, const string to);
        // Build proper request
        static string BuildProperMsg(const char* MsgFormat, ...);
        // Build proper ticket
        static string BuildProperTicket(const char* ticketFormat, ...);
        // Build proper Authp
        static string BuildProperAuthP(const char* authPFormat, ...);
        //Encrypt
        static string AESEncrypt(string PlainText,string mykey);
        //DEcrypt
        static string AESDecrypt(string CipherText,string mykey);
        //Build string from buffer
        static string BuildStringFromBuffer(const char *iobuf);
        // string constants
        static const string PlaneID;
        static const string TGS;
        static const string TimeStamp1;
        static const string TimeStamp2;
        static const string Ticket;
        static const string Auth;
        static const string msgDelimiters;
        static const string ticketDelimiters;
        static const string AuthPDelimiters;
        static const string Client;
        static const string PIG;
        static const string AURU;
        static const string Airports;
        static const string Utilities;
        static const string PlaneIDNotValid;
        static const string TimestampExceeded;
        static const string InvalidRequest;
        static const string InvalidAirportRequest;
        static const string AESModuleError;
        static const string KeyAS_TGS;
        static const string KeyTGS_V;
        static const string KeyC_TGS;
        static const string KeyC_V;
        static const string MessageTail;
    private:
        static const bool debugFlag;
};

const string Utility::PlaneID = "PlaneID";
const string Utility::TGS = "AURU";
const string Utility::TimeStamp1 = "TimeStamp1";
const string Utility::TimeStamp2 = "TimeStamp2";
const string Utility::Ticket = "Ticket";
const string Utility::Auth = "Auth";
const string Utility::MessageTail = "EOT";
const string Utility::msgDelimiters = "----";
const string Utility::ticketDelimiters = ">>>>";
const string Utility::AuthPDelimiters = "<<<<";
const string Utility::Client = "CLIENT";
const string Utility::PIG = "PIG";
const string Utility::AURU = "AURU";
const string Utility::Airports = "AIRPORTS";
const string Utility::Utilities = "UTILITIES";
const string Utility::PlaneIDNotValid = "PlaneID not validEOT";
const string Utility::TimestampExceeded = "Timestamp exceededEOT";
const string Utility::InvalidRequest = "Invalid RequestEOT";
const string Utility::InvalidAirportRequest = "Invalid Airport RequestEOT";
const string Utility::AESModuleError = "AES Module Error. Please try again.EOT";
const string Utility::KeyAS_TGS = "0192837456ngseby";
const string Utility::KeyTGS_V = "ngseby0192837456";
const string Utility::KeyC_TGS = "ngs0192837456eby";
const string Utility::KeyC_V = "n0192837gs456eby";
const bool Utility::debugFlag = false;

string Utility::BuildStringFromBuffer(const char *iobuf)
{
    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Buffer: %s. Size: %i.", iobuf, sizeof(iobuf));

    string output(1, iobuf[0]);

    for(int i=1;i<1024;i++)
    {
        if(iobuf[i] == 'E' && iobuf[i+1] == 'O' && iobuf[i+2] == 'T')
            break;
        output.append(1, iobuf[i]);
    }

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "String Built from Buffer: %s. Size: %i.", output.c_str(), output.size());

    return output;
}

string Utility::AESEncrypt(string PlainText,string mykey)
{

    // Key and IV setup
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ],
          iv[ CryptoPP::AES::BLOCKSIZE ];

    for(int i=0;i<CryptoPP::AES::DEFAULT_KEYLENGTH;i++)
    {
        if(i<mykey.length())
            key[i]=(int)mykey[i];
        else
            key[i]= 0x01;
    }
   // ::memset( key, 0x01, CryptoPP::AES::DEFAULT_KEYLENGTH );
    ::memset(  iv, 0x01, CryptoPP::AES::BLOCKSIZE );

    // Cipher Text Sink
    string CipherText;

    // Encryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption
        Encryptor( key, sizeof(key), iv );

    CryptoPP::StringSource( PlainText, true,
        new CryptoPP::StreamTransformationFilter( Encryptor,
            new CryptoPP::StringSink( CipherText )
        ) // StreamTransformationFilter
    ); // StringSource

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Plaintext: %s. Ciphertext: %s.", PlainText.c_str(), CipherText.c_str());

    return CipherText;
}

string Utility::AESDecrypt(string CipherText,string mykey)
{
    // Key and IV setup
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ],
          iv[ CryptoPP::AES::BLOCKSIZE ];

    for(int i=0;i<CryptoPP::AES::DEFAULT_KEYLENGTH;i++)
    {
        if(i<mykey.length())
            key[i]=(int)mykey[i];
        else
            key[i]= 0x01;
    }

    //::memset( key, 0x01, CryptoPP::AES::DEFAULT_KEYLENGTH );
    ::memset(  iv, 0x01, CryptoPP::AES::BLOCKSIZE );

    // Recovered Text Sink
    string RecoveredText;

    // Decryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption
        Decryptor( key, sizeof(key), iv );

    CryptoPP::StringSource( CipherText, true,
        new CryptoPP::StreamTransformationFilter( Decryptor,
            new CryptoPP::StringSink( RecoveredText )
        ) // StreamTransformationFilter
    ); // StringSink

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Ciphertext: %s. Plaintext: %i.", CipherText.c_str(), RecoveredText.c_str());

    return RecoveredText;
}

void Utility::WriteRecord(const char* record)
{
    ofstream recordFile("Record.txt", ios::app);
    recordFile << record;
    recordFile.close();
}

string Utility::ReplaceAll(string& context, const string from, const string to)
{
    size_t lookHere = 0;
    size_t foundHere;

    while((foundHere = context.find(from, lookHere)) != string::npos)
    {
        context.replace(foundHere, from.size(), to);
        lookHere = foundHere + to.size();
        Utility::PrintMessage(Utility::Utilities.c_str(), false, context.c_str());
    }

    return context;
}

string Utility::BuildProperMsg(const char* msgFormat, ...)
{
    char msg[1024];
    va_list vl;
    va_start(vl, msgFormat);
    vsprintf(msg, msgFormat, vl);
    va_end(vl);

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Recieve build msg", msg);
    string output(msg);
    Utility::ReplaceAll(output, ",", Utility::msgDelimiters);
    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Proper msg generated: %s", output.c_str());

    return output;
}

string Utility::BuildProperAuthP(const char* authPFormat, ...)
{
    char msg[1024];
    va_list vl;
    va_start(vl, authPFormat);
    vsprintf(msg, authPFormat, vl);
    va_end(vl);

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Recieve build authp msg", msg);
    string output(msg);
    Utility::ReplaceAll(output, ",", Utility::AuthPDelimiters);
    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Proper authp msg generated: %s", output.c_str());

    return output;
}

string Utility::BuildProperTicket(const char* ticketFormat, ...)
{
    char ticket[1024];
    va_list vl;
    va_start(vl, ticketFormat);
    vsprintf(ticket, ticketFormat, vl);
    va_end(vl);

    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Recieve build ticket: %s", ticket);
    string output(ticket);
    Utility::ReplaceAll(output, ",", Utility::ticketDelimiters);
    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Proper ticket generated: %s", output.c_str());

    return output;
}

void Utility::PrintMessage(string label, bool show, const char* msg, ...)
{
    if(Utility::debugFlag || show)
    {
        printf("> %s: ", label.c_str());

        if(Utility::debugFlag)
        {
            printf("DEBUG: ");
        }
        va_list v1;
        va_start(v1, msg);
        vprintf(msg, v1);
        va_end(v1);
        printf("\n");
    }
}

bool Utility::CheckTimeElapsedLimit(int timeStamp, int limit)
{
    Utility::PrintMessage(Utility::Utilities.c_str(), false, "Timelimit: %i. Time passed: %i.", limit, Utility::GetCurrentTime()-timeStamp);

    if(Utility::GetCurrentTime()-timeStamp > limit)
    {
        return true;
    }

    return false;
}

string Utility::GetPrettyTime()
{
    time_t now;
    now = time(NULL);
    return ctime(&now);
}

int Utility::GetCurrentTime()
{
    time_t ltime;
    ltime = time(NULL);
    return ltime;
}

void Utility::PrintMap(map<string, string> inMap, string left, string right)
{
    for(map<string,string>::iterator iter = inMap.begin(); iter != inMap.end(); ++iter)
    {
        cout << left << ":" << (*iter).first << " " << right << ":" << (*iter).second << endl;
    }
}

vector<string> Utility::GetObjectListFromFile(const char* filePath)
{
    vector<string> output;

    map<string, string> getObjectValue = Utility::GetMapFromFile(filePath);

    for(map<string,string>::iterator iter = getObjectValue.begin(); iter != getObjectValue .end(); ++iter)
    {
        output.push_back((*iter).first);
    }

    return output;
}

vector<string> Utility::GetAirportsFromFile(const char* filePath)
{
    vector<string> output;
    vector<string> temp;

    map<string, string> getObjectValue = Utility::GetMapFromFile(filePath);

    //Singapore Singapore,Sydney
    for(map<string,string>::iterator iter = getObjectValue.begin(); iter != getObjectValue .end(); ++iter)
    {
        temp.push_back((*iter).second);
        Utility::PrintMessage(Utility::Utilities.c_str(), false, (*iter).second.c_str());
    }

    //Singapore,Syney
    for(vector<string>::iterator iter1 = temp.begin(); iter1 != temp.end(); ++iter1)
    {
        vector<string> airportList = Utility::Tokenize(*iter1, ",");
        Utility::PrintMessage(Utility::Utilities.c_str(), false, (*iter1).c_str());

        //Singapore
        for(vector<string>::iterator iter2 = airportList.begin(); iter2 != airportList.end(); ++iter2)
        {
            if(!Utility::CheckVectorContains(output, *iter2))
            {
                output.push_back(*iter2);
                Utility::PrintMessage(Utility::Utilities.c_str(), false, (*iter2).c_str());
            }
        }
    }

    return output;
}

bool Utility::CheckVectorContains(vector<string> input, string value)
{
    for(vector<string>::iterator iter = input.begin(); iter != input.end(); ++iter)
    {
        Utility::PrintMessage(Utility::Utilities.c_str(), false, "%s : %s", (*iter).c_str(), value.c_str());
        if(strcmp((*iter).c_str(),value.c_str()) == 0)
        {
            return true;
        }
    }

    return false;
}

map<string, string> Utility::GetMapFromFile(const char * filePath)
{
    map<string, string> output;

    //opened file stream
    ifstream file;

    file.open(filePath);

    if(!file.is_open())
    {
        Utility::PrintMessage(Utility::Utilities.c_str(), false, "Could not open %s.", filePath);
        return output;
    }

    string line;
    vector<string> result;

    while(!file.eof())
    {
        getline(file, line);

        Utility::PrintMessage(Utility::Utilities.c_str(), false, line.c_str());
        result = Utility::Tokenize(line, " ");
        output[result[0]] = result[1];
        Utility::PrintMessage(Utility::Utilities.c_str(), false, "%s;%s", result[0].c_str(), result[1].c_str());
    }

    file.close();

    return output;
}

vector<string> Utility::Tokenize(const string& str, const string& delimiters)
{
    Utility::PrintMessage(Utility::Utilities.c_str(), false, str.c_str());
    vector<string> output;
    // Skip delimiters at beginning
    string::size_type lastPos =  str.find_first_not_of(delimiters, 0);

    // Find first "non-delimiter"
    string::size_type pos = str.find_first_of(delimiters, lastPos);

    while (string::npos != pos || string::npos != lastPos)
    {
        // Found a token, add it to the vector
        output.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters. Note te "not of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
    return output;
}
