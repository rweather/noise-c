/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "echo-common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if defined(__WIN32__) || defined(WIN32)
#include <winsock2.h>
typedef int socklen_t;
typedef BOOL sockopt_type;
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#define closesocket(x)  close((x))
typedef int sockopt_type;
#endif

int echo_verbose = 0;

/* Convert a Noise handshake protocol name into an Echo protocol id */
int echo_get_protocol_id(EchoProtocolId *id, const char *name)
{
    NoiseProtocolId nid;
    int ok = 1;

    memset(id, 0, sizeof(EchoProtocolId));
    if (noise_protocol_name_to_id(&nid, name, strlen(name)) != NOISE_ERROR_NONE)
        return 0;

    switch (nid.prefix_id) {
    case NOISE_PREFIX_STANDARD:     id->psk = ECHO_PSK_DISABLED; break;
    case NOISE_PREFIX_PSK:          id->psk = ECHO_PSK_ENABLED; break;
    default:                        ok = 0; break;
    }

    switch (nid.pattern_id) {
    case NOISE_PATTERN_NN:          id->pattern = ECHO_PATTERN_NN; break;
    case NOISE_PATTERN_KN:          id->pattern = ECHO_PATTERN_KN; break;
    case NOISE_PATTERN_NK:          id->pattern = ECHO_PATTERN_NK; break;
    case NOISE_PATTERN_KK:          id->pattern = ECHO_PATTERN_KK; break;
    case NOISE_PATTERN_NX:          id->pattern = ECHO_PATTERN_NX; break;
    case NOISE_PATTERN_KX:          id->pattern = ECHO_PATTERN_KX; break;
    case NOISE_PATTERN_XN:          id->pattern = ECHO_PATTERN_XN; break;
    case NOISE_PATTERN_IN:          id->pattern = ECHO_PATTERN_IN; break;
    case NOISE_PATTERN_XK:          id->pattern = ECHO_PATTERN_XK; break;
    case NOISE_PATTERN_IK:          id->pattern = ECHO_PATTERN_IK; break;
    case NOISE_PATTERN_XX:          id->pattern = ECHO_PATTERN_XX; break;
    case NOISE_PATTERN_IX:          id->pattern = ECHO_PATTERN_IX; break;
    default:                        ok = 0; break;
    }

    switch (nid.cipher_id) {
    case NOISE_CIPHER_CHACHAPOLY:   id->cipher = ECHO_CIPHER_CHACHAPOLY; break;
    case NOISE_CIPHER_AESGCM:       id->cipher = ECHO_CIPHER_AESGCM; break;
    default:                        ok = 0; break;
    }

    switch (nid.dh_id) {
    case NOISE_DH_CURVE25519:       id->dh = ECHO_DH_25519; break;
    case NOISE_DH_CURVE448:         id->dh = ECHO_DH_448; break;
    default:                        ok = 0; break;
    }

    switch (nid.hash_id) {
    case NOISE_HASH_SHA256:         id->hash = ECHO_HASH_SHA256; break;
    case NOISE_HASH_SHA512:         id->hash = ECHO_HASH_SHA512; break;
    case NOISE_HASH_BLAKE2s:        id->hash = ECHO_HASH_BLAKE2s; break;
    case NOISE_HASH_BLAKE2b:        id->hash = ECHO_HASH_BLAKE2b; break;
    default:                        ok = 0; break;
    }

    return ok;
}

/* Convert an Echo protocol id into a Noise protocol id */
int echo_to_noise_protocol_id(NoiseProtocolId *nid, const EchoProtocolId *id)
{
    int ok = 1;

    memset(nid, 0, sizeof(NoiseProtocolId));

    switch (id->psk) {
    case ECHO_PSK_DISABLED:         nid->prefix_id = NOISE_PREFIX_STANDARD; break;
    case ECHO_PSK_ENABLED:          nid->prefix_id = NOISE_PREFIX_PSK; break;
    default:                        ok = 0;
    }

    switch (id->pattern) {
    case ECHO_PATTERN_NN:           nid->pattern_id = NOISE_PATTERN_NN; break;
    case ECHO_PATTERN_KN:           nid->pattern_id = NOISE_PATTERN_KN; break;
    case ECHO_PATTERN_NK:           nid->pattern_id = NOISE_PATTERN_NK; break;
    case ECHO_PATTERN_KK:           nid->pattern_id = NOISE_PATTERN_KK; break;
    case ECHO_PATTERN_NX:           nid->pattern_id = NOISE_PATTERN_NX; break;
    case ECHO_PATTERN_KX:           nid->pattern_id = NOISE_PATTERN_KX; break;
    case ECHO_PATTERN_XN:           nid->pattern_id = NOISE_PATTERN_XN; break;
    case ECHO_PATTERN_IN:           nid->pattern_id = NOISE_PATTERN_IN; break;
    case ECHO_PATTERN_XK:           nid->pattern_id = NOISE_PATTERN_XK; break;
    case ECHO_PATTERN_IK:           nid->pattern_id = NOISE_PATTERN_IK; break;
    case ECHO_PATTERN_XX:           nid->pattern_id = NOISE_PATTERN_XX; break;
    case ECHO_PATTERN_IX:           nid->pattern_id = NOISE_PATTERN_IX; break;
    default:                        ok = 0;
    }

    switch (id->cipher) {
    case ECHO_CIPHER_CHACHAPOLY:    nid->cipher_id = NOISE_CIPHER_CHACHAPOLY; break;
    case ECHO_CIPHER_AESGCM:        nid->cipher_id = NOISE_CIPHER_AESGCM; break;
    default:                        ok = 0;
    }

    switch (id->dh) {
    case ECHO_DH_25519:             nid->dh_id = NOISE_DH_CURVE25519; break;
    case ECHO_DH_448:               nid->dh_id = NOISE_DH_CURVE448; break;
    default:                        ok = 0;
    }

    switch (id->hash) {
    case ECHO_HASH_SHA256:          nid->hash_id = NOISE_HASH_SHA256; break;
    case ECHO_HASH_SHA512:          nid->hash_id = NOISE_HASH_SHA512; break;
    case ECHO_HASH_BLAKE2s:         nid->hash_id = NOISE_HASH_BLAKE2s; break;
    case ECHO_HASH_BLAKE2b:         nid->hash_id = NOISE_HASH_BLAKE2b; break;
    default:                        ok = 0;
    }

    return ok;
}

/* Loads a binary private key from a file.  Returns non-zero if OK. */
int echo_load_private_key(const char *filename, uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "rb");
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "private key length is not supported\n");
        return 0;
    }
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (posn >= len) {
            fclose(file);
            fprintf(stderr, "%s: private key value is too long\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)ch;
    }
    if (posn < len) {
        fclose(file);
        fprintf(stderr, "%s: private key value is too short\n", filename);
        return 0;
    }
    fclose(file);
    return 1;
}

/* Loads a base64-encoded public key from a file.  Returns non-zero if OK. */
int echo_load_public_key(const char *filename, uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "rb");
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "public key length is not supported\n");
        return 0;
    }
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+') {
            digit = 62;
        } else if (ch == '/') {
            digit = 63;
        } else if (ch == '=') {
            break;
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            fclose(file);
            fprintf(stderr, "%s: invalid character in public key file\n", filename);
            return 0;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4) {
            if ((len - posn) < 3) {
                fclose(file);
                fprintf(stderr, "%s: public key value is too long\n", filename);
                return 0;
            }
            group_size = 0;
            key[posn++] = (uint8_t)(group >> 16);
            key[posn++] = (uint8_t)(group >> 8);
            key[posn++] = (uint8_t)group;
        }
    }
    if (group_size == 3) {
        if ((len - posn) < 2) {
            fclose(file);
            fprintf(stderr, "%s: public key value is too long\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 10);
        key[posn++] = (uint8_t)(group >> 2);
    } else if (group_size == 2) {
        if ((len - posn) < 1) {
            fclose(file);
            fprintf(stderr, "%s: public key value is too long\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 4);
    }
    if (posn < len) {
        fclose(file);
        fprintf(stderr, "%s: public key value is too short\n", filename);
        return 0;
    }
    fclose(file);
    return 1;
}

/* Connects to a remote echo server.  Returns the file descriptor or -1
   if an error occurs while creating the socket or trying to connect. */
int echo_connect(const char *hostname, int port)
{
    struct sockaddr_in addr;
    struct hostent *ent;
    int fd;
    sockopt_type opt;

    /* Look up the address of the remote party (IPv4 only at present) */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        ent = gethostbyname(hostname);
        if (!ent) {
            fprintf(stderr, "%s: Unknown hostname\n", hostname);
            return -1;
        }
        memcpy(&(addr.sin_addr), ent->h_addr_list[0], sizeof(addr.sin_addr));
    }

    /* Create the socket and set some useful options on it */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt TCP_NODELAY");
        closesocket(fd);
        return -1;
    }

    /* Connect to the remote party */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        closesocket(fd);
        return -1;
    }
    return fd;
}

#if !(defined(__WIN32__) || defined(WIN32))

static void sigchld_handler(int sig)
{
    /* Nothing to do here */
}

#endif

/* Accepts an incoming connection from an echo client.  Returns the file
   descriptor of the socket to use to communicate with the client.

   Internally this function will fork the process and return the file
   descriptor for the connection in the child.  The parent process will
   never return from this function. */
int echo_accept(int port)
{
    int listen_fd;
    int accept_fd;
    sockopt_type opt;
    struct sockaddr_in addr;
    socklen_t addrlen;

#if !(defined(__WIN32__) || defined(WIN32))
    /* We will need SIGCHLD signals to clean up child processes */
    signal(SIGCHLD, sigchld_handler);
#endif

    /* Create the listening socket and bind it to the port */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }
    opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        closesocket(listen_fd);
        exit(1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        closesocket(listen_fd);
        exit(1);
    }
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        closesocket(listen_fd);
        exit(1);
    }

    /* Loop forever waiting for incoming connections */
    accept_fd = -1;
    for (;;) {
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        accept_fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
#if defined(__WIN32__) || defined(WIN32)
        if (accept_fd >= 0) {
            /* Win32 doesn't have a direct equivalent to fork so merely
               close the listening socket and return.  This means that
               the server can only handle a single connection on Win32.
               Fix this later by using threads to handle clients instead. */
            closesocket(listen_fd);
            break;
        }
#else
        if (accept_fd >= 0) {
            /* Fork and return the new socket in the child */
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                closesocket(accept_fd);
                closesocket(listen_fd);
                exit(1);
            } else if (pid == 0) {
                /* In the child process */
                closesocket(listen_fd);
                break;
            } else {
                /* In the parent process */
                closesocket(accept_fd);
            }
        } else if (errno == EINTR) {
            /* Interrupted by a system call.  This is probably due to a
               child process terminating.  Clean up any waiting children. */
            int status;
            while (waitpid(-1, &status, WNOHANG) >= 0)
                ;   /* Do nothing */
        } else {
            perror("accept");
            closesocket(listen_fd);
            exit(1);
        }
#endif
    }

    /* Add some useful options to the incoming socket and then return */
    opt = 1;
    if (setsockopt(accept_fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt TCP_NODELAY");
        closesocket(accept_fd);
        exit(1);
    }
    return accept_fd;
}

static void echo_print_packet(const char *tag, const uint8_t *packet, size_t len)
{
    size_t index;
    printf("%s:", tag);
    for (index = 0; index < len; ++index) {
        printf(" %02x", packet[index]);
        if ((index % 16) == 15 && index != (len - 1))
            printf("\n   ");
    }
    printf("\n");
}

/* Recevies an exact number of bytes, blocking until they are all available.
   Returns non-zero if OK, zero if the connection has been lost. */
static int echo_recv_exact_internal(int fd, uint8_t *packet, size_t len)
{
    size_t received = 0;
    while (len > 0) {
        int size = recv(fd, (void *)packet, len, 0);
        if (size < 0) {
#if defined(__WIN32__) || defined(WIN32)
            return 0;
#else
            if (errno == EINTR || errno == EAGAIN)
                continue;
            perror("recv");
            return 0;
#endif
        } else if (size == 0) {
            return 0;
        } else {
            packet += size;
            len -= size;
            received += size;
        }
    }
    return received;
}

/* Recevies an exact number of bytes, blocking until they are all available.
   Returns non-zero if OK, zero if the connection has been lost. */
int echo_recv_exact(int fd, uint8_t *packet, size_t len)
{
    size_t received = echo_recv_exact_internal(fd, packet, len);
    if (received) {
        if (echo_verbose)
            echo_print_packet("Rx", packet, received);
    } else if (echo_verbose) {
        printf("Rx: EOF\n");
    }
    return received;
}

/* Receives a complete Noise packet, including the two-byte length prefix.
   Returns the length of the packet, zero if the connection has been lost
   or the packet is too large for the supplied buffer. */
size_t echo_recv(int fd, uint8_t *packet, size_t max_len)
{
    size_t size;
    if (max_len < 2)
        return 0;
    if (!echo_recv_exact_internal(fd, packet, 2))
        return 0;
    size = (((size_t)(packet[0])) << 8) | ((size_t)(packet[1]));
    if (size > (max_len - 2))
        return 0;
    size = echo_recv_exact_internal(fd, packet + 2, size);
    if (size)
        size += 2;
    if (echo_verbose)
        echo_print_packet("Rx", packet, size);
    return size;
}

/* Sends a complete Noise packet, including the two-byte length prefix.
   Returns non-zero if OK, zero if the connection has been lost. */
int echo_send(int fd, const uint8_t *packet, size_t len)
{
    int size;
    if (echo_verbose)
        echo_print_packet("Tx", packet, len);
    while ((size = send(fd, (const void *)packet, len, MSG_NOSIGNAL)) != (int)len) {
        if (size < 0) {
#if defined(__WIN32__) || defined(WIN32)
            return 0;
#else
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
                return 0;
            } else {
                perror("send");
                return 0;
            }
#endif
        } else {
            packet += size;
            len -= size;
        }
    }
    return 1;
}

/* Closes a socket */
void echo_close(int fd)
{
    closesocket(fd);
}
