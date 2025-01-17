#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>
#include <RRCConnectionSetupComplete.h>
#include <per_encoder.h>
#include <per_decoder.h>

#define PORT 8080

void log_message(const char *message) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
           t->tm_year + 1900,
           t->tm_mon + 1,
           t->tm_mday,
           t->tm_hour,
           t->tm_min,
           t->tm_sec,
           message);
}

void handle_client(int client_socket, struct sockaddr_in *client_addr) {
    char buffer[1024];
    ssize_t len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Error reading data");
        return;
    }

    // декодируем RRCConnectionRequest
    RRCConnectionRequest_t *req = NULL;
    asn_dec_rval_t dec_ret = uper_decode(NULL, &asn_DEF_RRCConnectionRequest, (void **)&req, buffer, len, 0, 0);

    if (dec_ret.code != RC_OK) {
        log_message("Error decoding RRCConnectionRequest");
        return;
    }

    log_message("Received RRCConnectionRequest");
    // отображаем детали ue-Identity
    printf("ue-Identity type: %d\n",
           req->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.present);

    //создаем и отправляем RRCConnectionSetup
    RRCConnectionSetup_t setup;
    memset(&setup, 0, sizeof(RRCConnectionSetup_t));
    setup.rrc_TransactionIdentifier = 1;
    setup.criticalExtensions.present = RRCConnectionSetup__criticalExtensions_PR_c1;
    setup.criticalExtensions.choice.c1.present = RRCConnectionSetup__criticalExtensions__c1_PR_rrcConnectionSetup_r8;

    asn_enc_rval_t enc_ret = uper_encode_to_buffer(
        &asn_DEF_RRCConnectionSetup, 
        NULL,
        &setup,
        buffer,
        sizeof(buffer)
    );

    if (enc_ret.encoded == -1) {
        log_message("Error encoding RRCConnectionSetup");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, req);
        return;
    }
    xer_fprint(stdout, &asn_DEF_RRCConnectionSetup, &setup);

    if (send(client_socket, buffer, enc_ret.encoded, 0) == -1) {
        perror("Send failed");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, req);
        return;
    }

    log_message("Sent RRCConnectionSetup");

    // прием и декодирование RRCConnectionSetupComplete
    len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Error reading RRCConnectionSetupComplete");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, req);
        return;
    }

    RRCConnectionSetupComplete_t *setup_complete = NULL;
    dec_ret = uper_decode(NULL, &asn_DEF_RRCConnectionSetupComplete, (void **)&setup_complete, buffer, len, 0, 0);

    if (dec_ret.code != RC_OK) {
        log_message("Error decoding RRCConnectionSetupComplete");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, req);
        return;
    }

    log_message("Received RRCConnectionSetupComplete");


    printf("Received RRCConnectionSetupComplete with PLMN-Identity: %ld\n",
           setup_complete->criticalExtensions.choice.c1.choice.rrcConnectionSetupComplete_r8.selectedPLMN_Identity);

    ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, req);
    ASN_STRUCT_FREE(asn_DEF_RRCConnectionSetupComplete, setup_complete);
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    // создаем сокет
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    log_message("Socket created");

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt SO_REUSEADDR failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt TCP_NODELAY failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_message("Socket options set");

    //привязываем к адресу и порту
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_message("Socket bound to port");

    // ожидаем входящих соединений
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_message("Server is listening");

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        char log_buffer[128];
        snprintf(log_buffer, sizeof(log_buffer), "Accepted connection from %s:%d", client_ip, ntohs(client_addr.sin_port));
        log_message(log_buffer);

        handle_client(client_socket, &client_addr);
        close(client_socket); // закрываем клиентский сокет после обработки
        log_message("Connection closed");
    }

    close(server_fd); // при завершении закрываем серверный сокет
    log_message("Server shutting down");

    return 0;
}