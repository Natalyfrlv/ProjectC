#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>
#include <RRCConnectionSetupComplete.h>
#include <per_encoder.h>
#include <per_decoder.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

void error_exit(const char* message, int sock) {
    perror(message);
    if (sock > 0) {
        close(sock);
    }
    exit(EXIT_FAILURE);
}

void log_data(const char* label, const char* data, size_t size) {
    printf("%s (size: %lu): ", label, size);
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    printf("\n");
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    // создаем сокет
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error_exit("Error creating socket", sock);
    }

    // настраиваем адрес сервера
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        error_exit("Invalid or unsupported address", sock);
    }

    // подключаемся к серверу
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error_exit("Error connecting to server", sock);
    }

    // инициализируем RRC Connection Request
    RRCConnectionRequest_t req;
    memset(&req, 0, sizeof(RRCConnectionRequest_t));
    req.criticalExtensions.present = RRCConnectionRequest__criticalExtensions_PR_rrcConnectionRequest_r8;
    req.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.present = InitialUE_Identity_PR_s_TMSI;

    uint8_t mmec_value[] = {1};
    req.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.s_TMSI.mmec.buf = mmec_value;
    req.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.s_TMSI.mmec.size = sizeof(mmec_value);

    uint8_t m_tmsi_value[] = {0, 0, 48, 57}; 
    req.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.s_TMSI.m_TMSI.buf = m_tmsi_value;
    req.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.s_TMSI.m_TMSI.size = sizeof(m_tmsi_value);

    // кодируем и отправляем RRC Connection Request
    asn_enc_rval_t enc_ret = uper_encode_to_buffer(&asn_DEF_RRCConnectionRequest, NULL, &req, buffer, BUFFER_SIZE);
    if (enc_ret.encoded == -1) {
        error_exit("Error in encoding RRC Connection Request", sock);
    }

    log_data("Sending RRC Connection Request", buffer, enc_ret.encoded);

    if (send(sock, buffer, enc_ret.encoded, 0) == -1) {
        error_exit("Error sending RRC Connection Request", sock);
    }

    // прием RRC Connection Setup
    ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        error_exit("Error receiving RRC Connection Setup", sock);
    }

    log_data("Received RRC Connection Setup", buffer, len);

    RRCConnectionSetup_t* setup = NULL;
    asn_dec_rval_t dec_ret = uper_decode(NULL, &asn_DEF_RRCConnectionSetup, (void **)&setup, buffer, len, 0, 0);

    if (dec_ret.code != RC_OK) {
        error_exit("Error decoding RRC Connection Setup", sock);
    }

    printf("Received RRC Connection Setup with transaction ID: %ld\n", setup->rrc_TransactionIdentifier);

    // инициализируем RRC Connection Setup Complete
    RRCConnectionSetupComplete_t setup_complete;
    memset(&setup_complete, 0, sizeof(RRCConnectionSetupComplete_t));
    setup_complete.rrc_TransactionIdentifier = setup->rrc_TransactionIdentifier;

    setup_complete.criticalExtensions.present = RRCConnectionSetupComplete__criticalExtensions_PR_c1;
    setup_complete.criticalExtensions.choice.c1.present = RRCConnectionSetupComplete__criticalExtensions__c1_PR_rrcConnectionSetupComplete_r8;
    setup_complete.criticalExtensions.choice.c1.choice.rrcConnectionSetupComplete_r8.selectedPLMN_Identity = 1;
    uint8_t nas_info[] = {0x01, 0x02, 0x03}; // Пример значения
    setup_complete.criticalExtensions.choice.c1.choice.rrcConnectionSetupComplete_r8.dedicatedInfoNAS.buf = nas_info;
    setup_complete.criticalExtensions.choice.c1.choice.rrcConnectionSetupComplete_r8.dedicatedInfoNAS.size = sizeof(nas_info);

    // кодируем и отправляем RRC Connection Setup Complete
    enc_ret = uper_encode_to_buffer(&asn_DEF_RRCConnectionSetupComplete, NULL, &setup_complete, buffer, BUFFER_SIZE);
    if (enc_ret.encoded == -1) {
        error_exit("Error encoding RRC Connection Setup Complete", sock);
    }

    xer_fprint(stdout, &asn_DEF_RRCConnectionSetup, setup);

    log_data("Sending RRC Connection Setup Complete", buffer, enc_ret.encoded);

    if (send(sock, buffer, enc_ret.encoded, 0) == -1) {
        error_exit("Error sending RRC Connection Setup Complete", sock);
    }

    printf("Successfully sent RRC Connection Setup Complete.\n");

    ASN_STRUCT_FREE(asn_DEF_RRCConnectionSetup, setup);

    close(sock); 

    return 0;
}