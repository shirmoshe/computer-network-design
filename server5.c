#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#define MULTICAST_IP "239.0.0.1"
#define UDP_PORT 9090
//#define TCP_IP "192.168.99.8"
#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define TIMEOUT 30

typedef struct {
    int socket;
    time_t last_activity;
    pthread_mutex_t lock;
    int server_key;
    int client_key; 
    int shared_key; 
    int g; 
    int p;
    int mcst_key; 
    char msg[BUFFER_SIZE];
} client_info_t;

// Shared parameters to handle communoation between threads
client_info_t clients[MAX_CLIENTS];
pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t udp_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t udp_cond = PTHREAD_COND_INITIALIZER;
char udp_buffer[BUFFER_SIZE];
int udp_ready = 0;  // Flag to indicate if there is data to send

// Function Declaration 
void *handle_udp(void *arg);



void *encrypt(char *msg, int key, char *encrypted_msg) {
    int i;
    for (i = 0; i < strlen(msg); i++) {
        encrypted_msg[i] = msg[i] ^ key;
    }
    encrypted_msg[i] = '\0';  // Null-terminate the encrypted message
}


void decrypt(char *msg, int key, char* decrypt_msg) {
    char *temp_pointer = decrypt_msg; 
    int i;
    for (i = 0; i < strlen(msg); i++) {
        temp_pointer[i] = msg[i] ^ key;
    }
    temp_pointer[i] = '\0';  // Null-terminate the decrypted message
    printf("IN DECRYPT: %s\n", temp_pointer);
}

// Function to handle communication with each client - 1 thread for each client 
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    char buffer[BUFFER_SIZE], buffer_data[BUFFER_SIZE];
    int type = -1;
    int client_index = -1;
    
    // Find the client index and initialize last activity time
    pthread_mutex_lock(&clients_lock);
    int i;
    for (i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].socket == -1) {
            clients[i].socket = client_socket;
            clients[i].last_activity = time(NULL);
            client_index = i;
            break;
        }
    }
    
    pthread_mutex_unlock(&clients_lock);
    
    if (client_index == -1) {
        printf("Max clients reached, rejecting client.\n");
        close(client_socket);
        pthread_exit(NULL);
    }

    // Initialize connection
    printf("Client conneccted\n");

    srand(time(0));
    int a =3+rand()%10 ;
    printf("Generated Integer a: %d\n", a);

    while (1) {
        // read the message
        ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            break;
        }       
        printf("<-- Recieve: %s\n", buffer);
        
        strcat(buffer_data, buffer); 
        // read the message type
        sscanf(buffer, "Message Type:(%d)", &type);
        printf("Type msg: %d\n", type);

        switch (type) {
        
        case 0:{
            // type JOIN 
            int key = ((int)pow(clients[client_index].g, a)) % clients[client_index].p;  // Calculate server_key as g^a mod p
            clients[client_index].server_key = key;
           // printf("--> Send: \nserver key: %d, p: %d, g: %d\n", clients[client_index].server_key, clients[client_index].p, clients[client_index].g);
            
            // send WELCOME message type 1 includ: g^a, p for calculate key
            char welcome_msg[BUFFER_SIZE];
            sprintf(welcome_msg, "Message Type:(1)WELCOME, server key: %d, p: %d, g: %d", clients[client_index].server_key, clients[client_index].p, clients[client_index].g); // type  - WELCOME
            printf("--> Send: %s\n", welcome_msg);
            send(client_socket, welcome_msg, strlen(welcome_msg), 0);  // Send welcome msg
            
            memset(buffer, 0, BUFFER_SIZE);

            break;
        }
            
        

        case 9:
            {   // type KEEP ALIVE
            // Update last activity time
            pthread_mutex_lock(&clients[client_index].lock);
            clients[client_index].last_activity = time(NULL);
            printf("time update:\n ");
            pthread_mutex_unlock(&clients[client_index].lock);
            
            memset(buffer, 0, BUFFER_SIZE);


            break;
            }
        case 2:{ 
            // type KEY(2)
            int client_key, multicast_key, encrypted_mc_key;
            sscanf(buffer, "Message Type:(2)KEY: %d\n", &client_key); // get g^b from user 
            clients[client_index].client_key = client_key;
            int shared_key = ((int)pow(client_key, a)) % clients[client_index].p;   // calc g^ab mod p
            clients[client_index].shared_key = shared_key;
    //        printf("<-- Received:\nclient key: %d, server key: %d, Shared key: %d\n", clients[client_index].client_key, clients[client_index].server_key, clients[client_index].shared_key);

            // Encrypt multicast key with the shared key 
            multicast_key = clients[client_index].mcst_key; 
            encrypted_mc_key = multicast_key ^ shared_key;

    //        printf("--> Send:\nmulticast key=%d, shared key=%d , encrypt key= %d\n", multicast_key,shared_key, encrypted_mc_key);
            char mc_key_msg[BUFFER_SIZE];
            sprintf(mc_key_msg, "Message Type:(3)MC_KEY: %d", encrypted_mc_key);
            printf("--> Send: %s\n", mc_key_msg);
            send(client_socket, mc_key_msg, strlen(mc_key_msg), 0); 
            
            memset(buffer, 0, BUFFER_SIZE);

            break;
        }
        case 4:{         

            char rcv_msg[BUFFER_SIZE], decrypt_msg[BUFFER_SIZE];
            sscanf(buffer, "Message Type:(4): The Encrypt Message is: %s\n", rcv_msg); 
            printf("Data is: %s\n", rcv_msg);

            //strcpy(decrypt_msg, decrypt(rcv_msg, shared_key));  // decrypt message wuth the shared key 
            decrypt(rcv_msg, clients[client_index].shared_key, decrypt_msg);
            
            printf("return from dec function\n");
            printf("decrypt_msg, %s\n", decrypt_msg);

            // Lock and copy the decrypted message to the shared buffer
            pthread_mutex_lock(&udp_lock);
            strcpy(udp_buffer, decrypt_msg);
            udp_ready = 1;  // Indicate that there is data to send
            pthread_cond_signal(&udp_cond);  // Signal the UDP thread
            pthread_mutex_unlock(&udp_lock);

            memset(buffer, 0, BUFFER_SIZE);
            
            break;
        }
        }
    }
}

void *monitor_clients(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    while (1) {
        sleep(1); // Check every second
        time_t now = time(NULL);

        pthread_mutex_lock(&clients_lock);
      int i;
        for (i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].socket != -1) {
                pthread_mutex_lock(&clients[i].lock);
                if (difftime(now, clients[i].last_activity) >= TIMEOUT) {
                    printf("Client %d timed out\n", i);
                    char goodbye_msg[BUFFER_SIZE];
                    sprintf(goodbye_msg,"Message Type:(99) GoodBye!\n");
                    printf("--> sent : %s\n",goodbye_msg);
                    send(client_socket, goodbye_msg,strlen(goodbye_msg),0);
                    close(clients[i].socket);
                    clients[i].socket = -1;
                }
                pthread_mutex_unlock(&clients[i].lock);
            }
        }
        pthread_mutex_unlock(&clients_lock);
    }
    pthread_exit(NULL);
}

void *handle_udp(void *arg) {

    printf("in UDP function\n");
    int udp_socket = *(int *)arg;
    struct sockaddr_in udp_addr;
    socklen_t client_len = sizeof(udp_addr);
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = inet_addr(MULTICAST_IP);
    udp_addr.sin_port = htons(UDP_PORT);
    char encrypted_msg[BUFFER_SIZE];
    
    while (1) {

        pthread_mutex_lock(&udp_lock);
        while (!udp_ready) {
            pthread_cond_wait(&udp_cond, &udp_lock);  // Wait for a signal, the mutex unlock untill the sognal arrive
            printf("get SIGNAL from tcp thread\n");
        }

        // Encrypt the message with the multicast key
        encrypt(udp_buffer, clients[0].mcst_key, encrypted_msg);  // Assuming clients[0] has the correct key
        printf("encrypt MULTICAST msg: %s\n", encrypted_msg);

        // Send the encrypted message over the UDP socket
        sendto(udp_socket, encrypted_msg, strlen(encrypted_msg), 0, (struct sockaddr *)&udp_addr, sizeof(udp_addr));
        printf("--> Send: %s\n", encrypted_msg);

        udp_ready = 0;  // Reset the flag
        pthread_mutex_unlock(&udp_lock);
    }

            return NULL; 
}
    
   

int main(int argc, char *argv[]) {
    int server_fd, new_socket, *client_socket, udp_socket;
    struct sockaddr_in address, udp_addr;
    int addrlen = sizeof(address);
    pthread_t thread_id, monitor_thread_id, multicast_thread_id, udp_thread_id;
    int ttl = 10;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_address>\n", argv[0]);
        return -1;
    }

    char *server_ip = argv[1];



    // Initialize DIFI HELMAN parameters
    srand(time(0));
    int g = rand() % 15;
    int p = rand() %15 ;  
    int multicast_key =rand() % 15;
    printf("Generate DH perameter:\ng = %d, p=%d, multicast key=%d\n", g, p, multicast_key);
    
    // Initialize clients array
    int i; 
    for (i = 0; i < MAX_CLIENTS; ++i) {
        clients[i].socket = -1;
        clients[i].g = g;
        clients[i].p = p;
        clients[i].mcst_key = multicast_key;
        pthread_mutex_init(&clients[i].lock, NULL);
    }

    // Create UDP socket
    if ((udp_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,sizeof(ttl));

    //==========================Set up socket end-point info for binding
   udp_addr.sin_family = AF_INET;
   udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);    /* Use wildcard IP address */
   udp_addr.sin_port = 0;	           	   /* Use any UDP port */

    if (bind(udp_socket, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == -1)
        { printf("Error: bind FAILED\n");
        }
    else
        { printf("OK: bind SUCCESS\n");
        }

    int len1;
    char line[100];
    struct sockaddr_in sock_addr;
    len1 = sizeof(sock_addr);
    
    getsockname(udp_socket, (struct sockaddr *) &sock_addr, &len1);
    printf("Socket s is bind to:\n");
    printf("  addr = %u\n", sock_addr.sin_addr.s_addr);
    printf("  port = %d\n", sock_addr.sin_port);


    // Create a thread to handle UDP communication
    if (pthread_create(&udp_thread_id, NULL, handle_udp, (void *)&udp_socket) != 0) {
        perror("pthread_create failed for UDP thread");
        close(udp_socket);
        exit(EXIT_FAILURE);
    }
    

    // Create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind server socket to the specified port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(server_ip); // use specific address
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Print the port and address of the server socket
    struct sockaddr_in server_address;
    socklen_t len = sizeof(server_address);
    if (getsockname(server_fd, (struct sockaddr *)&server_address, &len) == -1) {
        perror("getsockname failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on IP: %s, Port: %d\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));
    
    // // Create a thread to monitor client activity
    // if (pthread_create(&monitor_thread_id, NULL, monitor_clients, NULL) != 0) {
    //     perror("pthread_create failed");
    //     close(server_fd);
    //     exit(EXIT_FAILURE);
    // }

    // Accept and handle clients in parallel
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        client_socket = malloc(sizeof(int));
        *client_socket = new_socket;

        // Create a thread to monitor client activity
        if (pthread_create(&monitor_thread_id, NULL, monitor_clients, (void *)client_socket) != 0) {
            perror("pthread_create failed");
            close(server_fd);
            exit(EXIT_FAILURE);
    }

         // Create a new thread for each client
        if (pthread_create(&thread_id, NULL, handle_client, (void *)client_socket) != 0) {
            perror("pthread_create failed");
            close(new_socket);
            free(client_socket);
        }
        
        pthread_detach(thread_id);

    }

    if (new_socket < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    return 0;
}
