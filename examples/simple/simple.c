// gcc -Inoise-c-master/include noise-example.c noise-c-master/src/protocol/libnoiseprotocol.a
// https://linux.die.net/man/3/getopt
// https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/

#include <noise/protocol.h>

#include <stdio.h>    /* for printf */
#include <stdlib.h>   /* for malloc */
#include <getopt.h>   /* parsing arguments */
#include <sys/stat.h> /* file stat */

#include <netdb.h> /* for tcp */
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* inet_addr() */
#include <unistd.h>    /* read(), write(), close() */
#define MAX_MESSAGE_LEN 4096

int noise_handshake(int sockfd, NoiseHandshakeState *handshake);

void parse_args(int argc, char **argv);

int gen_load_keys(const char *file, uint8_t *key_pri, uint8_t *key_pub);
int load_pub_keys(const char *file, uint8_t *key_pub);

int file_to_key(const char *file_name, uint8_t *key, const size_t len);
int key_to_b64(char *buf, size_t buf_size, const uint8_t *key, size_t len);
int key_to_file(const char *file_name, const uint8_t *key, const size_t len);
int b64_to_key(const char *buf, size_t buf_len, uint8_t *key, const size_t key_len);

int server = 0;
int port = 7000;
char *my_file = "client";
char *remote_file = "server";
char *pattern = "Noise_KK_25519_AESGCM_SHA256"; //http://noiseprotocol.org/noise.html#handshake-pattern-validity
uint8_t psk[32] = {0x00};
char prologue[] = "test";

int main(int argc, char **argv)
{
    parse_args(argc, argv);

    uint8_t *priv_key = (uint8_t *)malloc(32);
    uint8_t *pub_key = (uint8_t *)malloc(32);
    gen_load_keys(my_file, priv_key, pub_key);

    uint8_t *remote_key = (uint8_t *)malloc(32);
    load_pub_keys(remote_file, remote_key);

    printf("my keys\n");
    char tmp[50];
    key_to_b64(tmp, sizeof(tmp), priv_key, 32);
    printf("privkey %i %s\n", 32, tmp);
    key_to_b64(tmp, sizeof(tmp), pub_key, 32);
    printf("pubkey  %i %s\n", 32, tmp);
    key_to_b64(tmp, sizeof(tmp), remote_key, 32);
    printf("remote  %i %s\n", 32, tmp);

    if (server)
    {
        int sockfd, connfd, len;
        struct sockaddr_in servaddr, cli;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1)
        {
            printf("socket creation failed...\n");
            return 1;
        }
        printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(port);

        if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0)
        {
            printf("socket bind failed...\n");
            return 1;
        }
        printf("Socket successfully binded..\n");

        if ((listen(sockfd, 5)) != 0)
        {
            printf("Listen failed...\n");
            return 1;
        }
        printf("Server listening..\n");
        len = sizeof(cli);

        connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
        if (connfd < 0)
        {
            printf("server accept failed...\n");
            return 1;
        }

        printf("create handshake\n");
        NoiseHandshakeState *handshake;
        noise_handshakestate_new_by_name(&handshake, pattern, NOISE_ROLE_RESPONDER);
        // noise_handshakestate_set_prologue(handshake, prologue, sizeof(prologue)); //http://noiseprotocol.org/noise.html#prologue

        NoiseDHState *dh;
        noise_handshakestate_set_pre_shared_key(handshake, psk, sizeof(psk));
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        noise_dhstate_set_keypair_private(dh, priv_key, 32);
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        noise_dhstate_set_public_key(dh, remote_key, 32);

        if (!noise_handshake(connfd, handshake))
        {
            close(connfd);
            close(sockfd);
            return 1;
        }

        NoiseCipherState *send_cipher = 0;
        NoiseCipherState *recv_cipher = 0;
        noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        noise_handshakestate_free(handshake);

        printf("server accept the client...\n");

        // Function for chatting between client and server
        char buff[MAX_MESSAGE_LEN];
        NoiseBuffer mbuf = {buff, 0, sizeof(buff)};
        for (;;)
        {
            if ((mbuf.size = recv(connfd, (void *)buff, sizeof(buff), 0)) < 0)
            {
                printf("error recv\n");
                return 0;
            }
            printf("RXm %i:", mbuf.size);
            for (int i = 0; i < mbuf.size; i++)
                printf(" %02X", (uint8_t)buff[i]);
            printf("\n");

            if (noise_cipherstate_decrypt(recv_cipher, &mbuf) != NOISE_ERROR_NONE)
            {
                printf("error read\n");
                return 0;
            }

            printf("From client: %.*sTo client : ", mbuf.size, buff);
            if (strncmp("exit", buff, 4) == 0)
            {
                printf("Server Exit...\n");
                break;
            }

            mbuf.size = 0;
            while ((buff[mbuf.size++] = getchar()) != '\n')
                ;

            if (noise_cipherstate_encrypt(send_cipher, &mbuf) != NOISE_ERROR_NONE)
            {
                printf("error write\n");
                return 1;
            }
            printf("TXm %i:", mbuf.size);
            for (int i = 0; i < mbuf.size; i++)
                printf(" %02X", (uint8_t)buff[i]);
            printf("\n");

            write(connfd, buff, mbuf.size);
        }
        close(connfd);
        close(sockfd);
    }
    else
    {
        printf("create handshake\n");
        NoiseHandshakeState *handshake;
        noise_handshakestate_new_by_name(&handshake, pattern, NOISE_ROLE_INITIATOR);
        // noise_handshakestate_set_prologue(handshake, prologue, sizeof(prologue)); //http://noiseprotocol.org/noise.html#prologue

        NoiseDHState *dh;
        noise_handshakestate_set_pre_shared_key(handshake, psk, sizeof(psk));
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        noise_dhstate_set_keypair_private(dh, priv_key, 32);
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        noise_dhstate_set_public_key(dh, remote_key, 32);

        printf("start connecting\n");
        int sockfd, connfd;
        struct sockaddr_in servaddr, cli;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1)
        {
            printf("socket creation failed...\n");
            return 1;
        }
        printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        servaddr.sin_port = htons(port);

        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        {
            printf("connection with the server failed...\n");
            return 1;
        }
        printf("connected to the server..\n");

        if (!noise_handshake(sockfd, handshake))
            return 1;

        NoiseCipherState *send_cipher = 0;
        NoiseCipherState *recv_cipher = 0;
        noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        noise_handshakestate_free(handshake);

        // function for chat
        char buff[MAX_MESSAGE_LEN];
        NoiseBuffer mbuf = {buff, 0, sizeof(buff)};
        for (;;)
        {
            printf("Enter the string : ");
            mbuf.size = 0;
            while ((buff[mbuf.size++] = getchar()) != '\n')
                ;

            if (noise_cipherstate_encrypt(send_cipher, &mbuf) != NOISE_ERROR_NONE)
            {
                printf("error write\n");
                return 1;
            }
            printf("TXm %i:", mbuf.size);
            for (int i = 0; i < mbuf.size; i++)
                printf(" %02X", (uint8_t)buff[i]);
            printf("\n");

            write(sockfd, buff, mbuf.size);

            if ((mbuf.size = recv(sockfd, (void *)buff, sizeof(buff), 0)) < 0)
            {
                printf("error recv\n");
                return 0;
            }
            printf("RXm %i:", mbuf.size);
            for (int i = 0; i < mbuf.size; i++)
                printf(" %02X", (uint8_t)buff[i]);
            printf("\n");

            if (noise_cipherstate_decrypt(recv_cipher, &mbuf) != NOISE_ERROR_NONE)
            {
                printf("error read\n");
                return 1;
            }

            printf("From Server : %.*s", mbuf.size, mbuf.data);
            if ((strncmp(buff, "exit", 4)) == 0)
            {
                printf("Client Exit...\n");
                break;
            }
        }
        close(sockfd);
    }

    return 0;
}

int noise_handshake(int sockfd, NoiseHandshakeState *handshake)
{
    NoiseBuffer mbuf;
    uint8_t message[MAX_MESSAGE_LEN];
    noise_handshakestate_start(handshake);
    int action = noise_handshakestate_get_action(handshake);
    while (1)
    {
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            printf("noise write message\n");
            noise_buffer_set_output(mbuf, message, sizeof(message));
            noise_handshakestate_write_message(handshake, &mbuf, NULL);
            printf("TXh %i:", mbuf.size);
            for (int i = 0; i < mbuf.size; i++)
                printf(" %02X", message[i]);
            printf("\n");
            send(sockfd, (const void *)message, mbuf.size, MSG_NOSIGNAL);
            action = noise_handshakestate_get_action(handshake);
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            printf("noise read message\n");
            int size;
            if ((size = recv(sockfd, (void *)message, sizeof(message), 0)) < 0)
            {
                printf("error recv\n");
                return 0;
            }
            printf("RXh %i:", size);
            for (int i = 0; i < size; i++)
                printf(" %02X", message[i]);
            printf("\n");
            noise_buffer_set_input(mbuf, message, size);
            noise_handshakestate_read_message(handshake, &mbuf, NULL);
            action = noise_handshakestate_get_action(handshake);
        }
        else
            break;
    }
    if (noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT)
    {
        printf("protocol handshake failed\n");
        return 0;
    }
    return 1;
}

int gen_load_keys(const char *file, uint8_t *key_pri, uint8_t *key_pub)
{
    char *file_pub = malloc(sizeof(file) + 4);
    sprintf(file_pub, "%s.pub", file);

    NoiseDHState *dh;
    noise_dhstate_new_by_name(&dh, "25519");

    size_t priv_len = noise_dhstate_get_private_key_length(dh);
    size_t pub_len = noise_dhstate_get_public_key_length(dh);

    struct stat buffer;
    if (stat(file, &buffer) < 0)
    {
        printf("generate new private key\n");
        noise_dhstate_generate_keypair(dh);
        noise_dhstate_get_keypair(dh, key_pri, priv_len, key_pub, pub_len);
        key_to_file(file, key_pri, priv_len);
        key_to_file(file_pub, key_pub, pub_len);
    }
    else
    {
        printf("found private key\n");
        file_to_key(file, key_pri, priv_len);
        noise_dhstate_set_keypair_private(dh, key_pri, priv_len);
        noise_dhstate_get_keypair(dh, key_pri, priv_len, key_pub, pub_len);
    }

    free(file_pub);
    return 1;
}

int load_pub_keys(const char *file, uint8_t *key_pub)
{
    char *file_pub = malloc(sizeof(file) + 4);
    sprintf(file_pub, "%s.pub", file);

    NoiseDHState *dh;
    noise_dhstate_new_by_name(&dh, "25519");

    size_t priv_len = noise_dhstate_get_private_key_length(dh);
    size_t pub_len = noise_dhstate_get_public_key_length(dh);

    struct stat buffer;
    if (stat(file_pub, &buffer) < 0)
    {
        printf("No public key generating new\n");
        noise_dhstate_generate_keypair(dh);
        uint8_t *key_pri = (uint8_t *)malloc(priv_len);
        noise_dhstate_get_keypair(dh, key_pri, priv_len, key_pub, pub_len);
        key_to_file(file, key_pri, priv_len);
        key_to_file(file_pub, key_pub, pub_len);
        free(key_pri);
    }
    else
    {
        printf("found public key\n");
        file_to_key(file_pub, key_pub, pub_len);
    }

    free(file_pub);
    return 1;
}

int key_to_file(const char *file_name, const uint8_t *key, const size_t len)
{
    FILE *file = fopen(file_name, "w");
    int buf_size = (len * 4 / 3) + 1;
    char *tmp = malloc(buf_size);
    key_to_b64(tmp, buf_size, key, len);

    int results = fputs(tmp, file);
    if (results == EOF)
    {
        printf("error writing key to file\n");
        return 0;
    }
    fclose(file);
}

int key_to_b64(char *file, size_t file_size, const uint8_t *key, const size_t len)
{
    static char const base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if ((file_size * 3) + 1 < len * 4)
    {
        printf("error key_to_b64 char too short\n");
        return 0;
    }

    int i, j = 0;
    for (i = 0; i < (file_size / 4); i++)
    {
        if (len < i * 3 + 3)
            break;

        file[i * 4] = base64_chars[(key[i * 3] >> 2) & 0x3F];
        file[i * 4 + 1] = base64_chars[(key[i * 3] << 4) & 0x3F | ((key[i * 3 + 1] >> 4) & 0x0F)];
        file[i * 4 + 2] = base64_chars[(key[i * 3 + 1] << 2) & 0x3F | ((key[i * 3 + 2] >> 6) & 0x0F)];
        file[i * 4 + 3] = base64_chars[key[i * 3 + 2] & 0x3F];
    }

    if (len % 3 == 1)
    {
        file[i * 4] = base64_chars[(key[i * 3] >> 2) & 0x3F];
        file[i * 4 + 1] = base64_chars[(key[i * 3] << 4) & 0x3F];
        file[i * 4 + 2] = '=';
        file[i * 4 + 3] = '=';
        i++;
    }
    else if (len % 3 == 2)
    {
        file[i * 4] = base64_chars[(key[i * 3] >> 2) & 0x3F];
        file[i * 4 + 1] = base64_chars[(key[i * 3] << 4) & 0x3F | ((key[i * 3 + 1] >> 4) & 0x0F)];
        file[i * 4 + 2] = base64_chars[(key[i * 3 + 1] << 2) & 0x3F];
        file[i * 4 + 3] = '=';
        i++;
    }
    else if (len % 3 > 2)
    {
        file[i * 4] = base64_chars[(key[i * 3] >> 2) & 0x3F];
        file[i * 4 + 1] = base64_chars[(key[i * 3] << 4) & 0x3F | ((key[i * 3 + 1] >> 4) & 0x0F)];
        file[i * 4 + 2] = base64_chars[(key[i * 3 + 1] << 2) & 0x3F | ((key[i * 3 + 2] >> 6) & 0x0F)];
        file[i * 4 + 3] = base64_chars[key[i * 3 + 2] & 0x3F];
        i++;
    }

    file[i * 4] = 0;
    return 1;
}

int file_to_key(const char *file_name, uint8_t *key, size_t len)
{
    FILE *fp = fopen(file_name, "rb");
    if (!fp)
        perror(file_name), exit(1);

    fseek(fp, 0L, SEEK_END);
    long lSize = ftell(fp);
    rewind(fp);

    char *buffer = malloc(lSize + 1); /* allocate memory for entire content */

    if (1 != fread(buffer, lSize, 1, fp)) /* copy the file into the buffer */
        fclose(fp), free(buffer), fputs("entire read fails", stderr), exit(1);

    b64_to_key(buffer, lSize, key, len); /* decode b64 key from buffer */

    fclose(fp);
    free(buffer);
}

int b64_to_key(const char *file, size_t file_len, uint8_t *key, size_t key_len)
{
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    for (int i = 0; i < file_len; i++)
    {
        ch = file[i];
        if (ch >= 'A' && ch <= 'Z')
            digit = ch - 'A';

        else if (ch >= 'a' && ch <= 'z')
            digit = ch - 'a' + 26;

        else if (ch >= '0' && ch <= '9')
            digit = ch - '0' + 52;

        else if (ch == '+')
            digit = 62;

        else if (ch == '/')
            digit = 63;

        else if (ch == '=')
            break;

        else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
        {
            fprintf(stderr, "invalid character in public key file\n");
            return 0;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4)
        {
            if ((key_len - posn) < 3)
            {
                fprintf(stderr, "public key value is too long\n");
                return 0;
            }
            group_size = 0;
            key[posn++] = (uint8_t)(group >> 16);
            key[posn++] = (uint8_t)(group >> 8);
            key[posn++] = (uint8_t)group;
        }
    }
    if (group_size == 3)
    {
        if ((key_len - posn) < 2)
        {
            fprintf(stderr, "public key value is too long\n");
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 10);
        key[posn++] = (uint8_t)(group >> 2);
    }
    else if (group_size == 2)
    {
        if ((key_len - posn) < 1)
        {
            fprintf(stderr, "public key value is too long\n");
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 4);
    }
    if (posn < key_len)
    {
        fprintf(stderr, "public key value is too short\n");
        return 0;
    }
    return 1;
}

void parse_args(int argc, char **argv)
{
    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"server", no_argument, 0, 's'},
        {"keyfile", required_argument, 0, 'k'},
        {0, 0, 0, 0}};

    while ((c = getopt_long(argc, argv, "sk:p:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 's':
            server = 1;
            my_file = "server";
            remote_file = "client";
            break;

        case 'k':
            my_file = optarg;
            break;

        case 'p':
            pattern = "NoisePSK_KK_25519_AESGCM_SHA256";
            int psk_size = 32;
            if (psk_size > strlen(optarg))
                psk_size = strlen(optarg);
            memcpy(psk, optarg, psk_size);
            printf("psk %i: %s\n", sizeof(psk), psk);
            break;

        case '?':
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
    if (server)
    {
        printf("mode server\n");
        if (optind < argc)
        {
            printf("port %s\n", argv[optind]);
            port = atoi(argv[optind]);
        }
    }
    else
    {
        printf("mode client\n");
    }
}
