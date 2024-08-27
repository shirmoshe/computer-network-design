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
#include <netinet/in.h>
#include <netinet/ip.h>


#define MULTICAST_IP "239.0.0.1"
#define MULTICAST_PORT 9090
#define KEEP_ALIVE 10
#define TIMEOUT 30
#define PORT 8080              // The port number on which the server is listening
#define BUFFER_SIZE 1024       // Size of the buffer to store messages

// Shared parameters to handle communoation between threads
int global_multicast_key = 0;

struct ip_mreq_1 {
    struct in_addr imr_multiaddr;  //IP multicast group address 
    struct in_addr imr_interface;  // IP address of local interface 
    struct in_addr imr_sourceaddr; // IP address of multicast source 
};

int use_flag = 0;

typedef struct {
    int sock;
    int udp_sock;
    int id;
    int shared_key;
    int server_key;
    int client_key; 
    int mcst_key; 
    time_t server_last_activity;
    pthread_mutex_t lock;

} thread_args_t;

char *encrypt(char *msg, int key) {
    static char encrypted_msg[BUFFER_SIZE];
    int i;
    for (i = 0; i < strlen(msg); i++) {
        encrypted_msg[i] = msg[i] ^ key;
    }
    encrypted_msg[i] = '\0';  // Null-terminate the encrypted message
  //  printf("IN ENCRYPT MSG: %s\n", encrypted_msg);
    return encrypted_msg;
}

void decrypt(char *msg, int key, char* decrypt_msg) {
    char *temp_pointer = decrypt_msg; 
    int i;
    for (i = 0; i < strlen(msg); i++) {
        temp_pointer[i] = msg[i] ^ key;
    }
    temp_pointer[i] = '\0';  // Null-terminate the decrypted message
   // printf("IN DECRYPT: %s\n", temp_pointer);
}

void *TCP_communication(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int sock = args->sock;
    int id = args->id;
    char buffer[BUFFER_SIZE] = {0};
    int type, ready=0;
    char join_msg[BUFFER_SIZE];
    
    // Send join message to the server  
    sprintf(join_msg, "Message Type:(0)Client joining, my id: %d", id); // type 0 - JOIN
    printf("--> Send: %s\n", join_msg);
    send(sock, join_msg, strlen(join_msg), 0);  // Send join message to server

    while (1){ // add while the connection to server is valid

        // read the message
        ssize_t bytes_read = read(sock, buffer, sizeof(buffer) - 1);
        //if (bytes_read <= 0) {
        //    break;
        //}
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                printf("Server disconnected. Exiting TCP communication thread.\n");
            } else {
                perror("read failed");
            }
            pthread_exit(NULL);
        }     



        printf("<-- Recieve: %s\n", buffer);

        // Read the message type
        sscanf(buffer, "Message Type:(%d)", &type);
    //    printf("Type msg: %d\n", type); 
        
        
        switch (type){

            case 1: 
                // type WELCOME
                int key, g, p, shared_key, client_key, server_key;
                // Extract key, g, and p from the welcome message
                sscanf(buffer, "Message Type:(1)WELCOME, server key: %d, p: %d, g: %d", &server_key, &p, &g);

                // Generate b, calculate g^ab mod p
                srand(time(0));
                int b = 3+ rand() %10 ;
                client_key = (int)pow(g, b) % p;
                shared_key = ((int)pow(server_key, b)) % p;
                args-> shared_key = shared_key;
                printf("Generated Integer b: %d\nclient key: %d, server key: %d, shared key:%d\n", b, client_key, server_key, shared_key);

                // Send key to server
                char key_msg[BUFFER_SIZE];
                sprintf(key_msg, "Message Type:(2)KEY: %d", client_key); // type 2 - KEY
                printf("--> Send: %s\n", key_msg);
                send(sock, key_msg, strlen(key_msg), 0);  // Send g^b to server
                
                memset(buffer, 0, BUFFER_SIZE);

                break;
            

            case 3: 
                // type MC KEY
                int sleep_flag = 0;
                int encrypted_mc_key;
                char answer= 'N';
                char msg_buff[BUFFER_SIZE], input_msg[BUFFER_SIZE], encrypt_msg[BUFFER_SIZE];

                sscanf(buffer, "Message Type:(3)MC_KEY: %d", &encrypted_mc_key);
                int multicast_key = encrypted_mc_key ^ (args->shared_key);
                args-> mcst_key= multicast_key;
                global_multicast_key = multicast_key;

                printf("Decrypted multicast key: %d\n", multicast_key);
                printf("Client successfully switched keys\n");
                
                memset(buffer, 0, BUFFER_SIZE);

                while (1)
                {
                    if (sleep_flag){
                        sleep(5);
                    }
                    sleep_flag = 1;
                    printf("If you want to send encrypt message to the group press y: \n");
                    
                    scanf(" %c", &answer);
                    use_flag = 1;
                    if(answer == 'y'){
                        printf("Enter your message: \n");
                        scanf("%s", input_msg); 
                        strcpy(encrypt_msg, encrypt(input_msg, args->shared_key));  // Encrypt the message using the shared key
                        //memset(msg_buff, 0, BUFFER_SIZE);
                        char msg_buff_new[BUFFER_SIZE];
                        int max = 100;
                        char tranc_msg[max + 1];
                        printf("this is enctypppy: %s\n",encrypt_msg);
                        strncpy(tranc_msg,encrypt_msg,max);
                        tranc_msg[max] = '\0';
                        snprintf(msg_buff_new,sizeof(msg_buff_new),"Message Type:(4): The Encrypt Message is: %s\n", tranc_msg);
                        //sprintf(msg_buff, "Message Type:(4)Multicast MSG, DATA: %s", encrypt_msg); 
                        printf("--> Send: %s\n", msg_buff_new);
                        send(sock, msg_buff_new, strlen(msg_buff_new), 0);  // Send encrypt msg to the server
                        use_flag =0;
                        
                    }

                    else{
                        printf("wrong answer\nIf you want to send encrypt message to the group press Y: \n");
                        scanf(" %c", &answer);
                    }
                }

                break;


            case 7:
                printf("in case 7\n");
                pthread_mutex_lock(&(args->lock));
                args->server_last_activity = time(NULL);
                pthread_mutex_unlock(&(args->lock));
                
                memset(buffer, 0, BUFFER_SIZE);

                break;

            case 99:
                printf("Thank you for your Participate and Come back soon!");
                
            default:
                printf("Unknown message type: %d\n", type);
                break;
        }
    }    
}

void *send_keep_alive(void *arg) {
    printf("in KEEP ALIVE thread\n");
    int sock = *(int *)arg;
    while (1) {
        sleep(KEEP_ALIVE); 
        char keep_alive_msg[] = "Message Type:(9)KEEP ALIVE";  // type 9 - keep alive
        if (use_flag){
        send(sock, keep_alive_msg, strlen(keep_alive_msg), 0);  // Send keep alive message to server
        printf("\n--> Send: %s\n", keep_alive_msg);
        }
    }
    pthread_exit(NULL);

}


void *UDP_communication(void *arg) {

    int udp_sock = *(int *)arg, src_addr_len, len;
    struct sockaddr_in udp_addr, server_addr;
    struct ip_mreq_1 mreq;
    char udp_buffer[BUFFER_SIZE], decrypt_msg[BUFFER_SIZE];
    int true = 1;
    struct hostent *host_entry_ptr;
    

    // Create UDP socket
    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed");
        pthread_exit(NULL);
    }

    // Allow multiple sockets to use the same PORT number
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true)) < 0) {
        perror("Setting SO_REUSEADDR error");
        close(udp_sock);
        pthread_exit(NULL);
    }

    // Set up the multicast group address
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Accept multicast from any interface
    udp_addr.sin_port = htons(MULTICAST_PORT);
    
    
    // Bind to the multicast port
    if (bind(udp_sock, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_sock);
        pthread_exit(NULL);
    }
    
    // Join the multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_IP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(udp_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP error");
        close(udp_sock);
        pthread_exit(NULL);
    }

    printf("Join succecsefuly to UDP socket\n");

    while (1) {
        ssize_t len = recvfrom(udp_sock, udp_buffer, BUFFER_SIZE, 0, NULL, 0);
        if (len < 0) {
            perror("recvfrom failed");
            continue;
        }

        udp_buffer[len] = '\0';
        printf("\n<-- Received: UDP message: %s\n", udp_buffer);
    
    
        decrypt(udp_buffer, global_multicast_key, decrypt_msg);

        printf("Decrypt UDP message: %s\n", decrypt_msg);
        
        }

}


    
int main(int argc, char *argv[]) {
    pthread_t comm_thread_id, keep_alive_thread_id, udp_thread_id;
    int sock = 0, udp_sock = 0 ;                       
    struct sockaddr_in serv_addr, udp_addr;       // Server address structure

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_address>\n", argv[0]);
        return -1;
    }

    char *server_address = argv[1];
    //char *server_address = "10.0.2.15";
  

    printf("Hello Welcome to Our Safe Chat Group\n");
    printf("Please Enter Your host ID: (expected value 1-10): ");
    int id;
    scanf("%d", &id);

    // =================== Create TCP socket ========================
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;  
    serv_addr.sin_port = htons(PORT);  // Set port number (the port that the server listens on)

    // Convert server addresses from text to binary form
    if (inet_pton(AF_INET, server_address, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Initial connection
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {  // Connect to server
        printf("\nConnection Failed \n");
        return -1;
    }

    // Print the port and address the client will connect to
    printf("Connecting to server at IP: %s, Port: %d\n", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

    // Create a structure to hold the TCP socket and id
    thread_args_t args;
    args.sock = sock;
    args.udp_sock = udp_sock;
    args.id = id;
    args.server_last_activity = time(NULL);


    // =================== Create UDP socket ========================
    printf("before create a udp thread\n");
    // Create a thread to handle UDP communication
    if (pthread_create(&udp_thread_id, NULL, UDP_communication, (void *)&udp_sock) != 0) {
        printf("Failed to create UDP thread\n");
        return -1;
    }

    // Create a thread to send keep alive messages to the server
    if (pthread_create(&keep_alive_thread_id, NULL, send_keep_alive, (void *)&sock) != 0) {
        printf("Failed to create keep alive thread\n");
        return -1;
    }

    // Create a thread to handle communication with the server
    if (pthread_create(&comm_thread_id, NULL, TCP_communication, (void *)&args) != 0) {
        printf("Failed to create thread\n");
        return -1;
    }


    // Wait for the all threads to finish
    pthread_join(keep_alive_thread_id, NULL);
    pthread_join(comm_thread_id, NULL);
    pthread_join(udp_thread_id, NULL);

    return 0;  
}
