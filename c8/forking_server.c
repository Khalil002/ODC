#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdio.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>


char buffer[0x300];

void get_name(int fd, char *local_buf){
  dprintf(fd, "What is your name?\n");
  read(fd, buffer, 0x300);
  memcpy(local_buf, buffer, 0x300);
}

void prog(int fd, int timeout){
  char local_buf[300];

  alarm(timeout);
  get_name(fd, local_buf);
  write(fd, "Hello Mr.", 9); 
  write(fd, local_buf, strlen(local_buf));
  write(fd, "\n", 1);
}

// Signal handler for SIGCHLD to reap zombie processes
void sigchld_handler(int signo) {
    // Use waitpid in a loop to reap all child processes that have terminated
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main()
{
    int server_sockfd, client_sockfd;
    int server_len, client_len;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    const char *timeout_str = getenv("TIMEOUT");
    int timeout;

    // Set timeout
    if (timeout_str != NULL) {
        timeout = atoi(timeout_str);
        if (timeout <= 0)
            timeout = 60;
    } else
        timeout = 60;

    // Set up SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Automatically restart interrupted system calls
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Allow the server to reuse the address/port (optional, but recommended for development/testing)
    int optval = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(server_sockfd);
        exit(1);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(4000);
    server_len = sizeof(server_address);

    // Bind the socket and check if the port is already in use
    if (bind(server_sockfd, (struct sockaddr *)&server_address, server_len) < 0) {
        perror("bind failed: port may already be in use");
        close(server_sockfd);
        exit(1);
    }

    /* Create a connection queue, ignore child exit details and wait for
    clients. */
    if (listen(server_sockfd, 5) < 0) {
        perror("listen failed");
        close(server_sockfd);
        exit(1);
    }

    while(1) {
        printf("server waiting\n");

        /* Accept connection. */
        client_len = sizeof(client_address);
        client_sockfd = accept(server_sockfd,(struct sockaddr *)&client_address, &client_len);

        /* Fork to create a process for this client and perform a test to see
        whether we're the parent or the child. */
        if(fork() == 0) {
            if(mprotect((char*)((long)buffer & 0xfffff000), 0x1000, PROT_WRITE | PROT_EXEC | PROT_READ) == -1){
              perror("mprotect");
            }

            /* If we're the child, we can now read/write to the client on
            client_sockfd. */
            write(client_sockfd,"  _________                                \n /   _____/ ______________  __ ___________ \n \\_____  \\_/ __ \\_  __ \\  \\/ // __ \\_  __ \\\n /        \\  ___/|  | \\/\\   /\\  ___/|  | \\/\n/_______  /\\___  >__|    \\_/  \\___  >__|   \n        \\/     \\/                 \\/       \n\n\n", 266);
            prog(client_sockfd, timeout);
            close(client_sockfd);
            exit(0);
        }

        /* Otherwise, we must be the parent and our work for this client is
        finished. */
        else {
            close(client_sockfd);
        }
    }
}
