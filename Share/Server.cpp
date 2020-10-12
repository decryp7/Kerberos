#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define	LENGTH	1024

class Server
{
public :
    void StartServer(const char *serverName, void *(*handler)(void *), int port);
private :
    struct sockaddr_in server_sockaddr;
	struct sockaddr_in client_sockaddr;
	pthread_t a_thread;
	char	myname[256];
	int   s, ds, rc;
	socklen_t arg;
	int	hp;
};

//Start server with its identifier, message handler and its port
void Server::StartServer(const char *serverName, void *(*handler)(void *), int port)
{
    //server_sockaddr.sin_family = AF_INET;
	hp=gethostname(myname, 256);
	memset((char *)&server_sockaddr, 0, sizeof(struct sockaddr_in));
        server_sockaddr.sin_family = hp;
	server_sockaddr.sin_port   = htons(port);

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1)
	{
		perror("socket");
		exit(1);
	}

	rc = bind(s, (struct sockaddr *) & server_sockaddr, sizeof (server_sockaddr));
	if (rc == -1)
	{
		perror("bind");
		exit(1);
	}

	rc = listen(s, 5);
	if (rc == -1)
	{
		perror("listen");
		exit(1);
	}

    printf("%s is listening at port %d.\n", serverName, port);

	for(;;)
	{
		arg = sizeof (client_sockaddr);
		ds = accept(s, (struct sockaddr *) & client_sockaddr, &arg);
		if (ds == -1)
		{
			perror("accept");
			close(s);
			exit(1);
		}

		//printf("%s heard something coming.\n", serverName);

		pthread_create(&a_thread, NULL, handler, (void*)&ds);
	}
	//return(0);
}



