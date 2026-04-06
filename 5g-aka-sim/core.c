#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"
#include "milenage.h"

// 寫死 Core 端的金鑰資料
AkaConfig core_config = {
    .k   = {0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC},
    .opc = {0xE8, 0xED, 0x28, 0x9D, 0xEB, 0xA9, 0x52, 0xE4, 0x28, 0x3B, 0x54, 0xE8, 0x8E, 0x61, 0x83, 0xCA},
    .sqn = {0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
    .amf = {0x80, 0x00},
    .snn = "5G:mnc092.mcc466.3gppnetwork.org"
};

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    AuthPacket packet;

    // 1. 建立 TCP Server
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    
    printf("[Core] 等待 UE 連線...\n");
    client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    printf("[Core] UE 已連線！\n");

    // 2. 接收 Trigger
    recv(client_socket, &packet, sizeof(AuthPacket), 0);
    if (packet.msg_type == MSG_AUTH_TRIGGER) {
        printf("[Core] 收到認證請求，準備出題...\n");

        // 隨機產生 16 bytes RAND (使用 /dev/urandom)
        FILE *fp = fopen("/dev/urandom", "r");
        if (fp == NULL) {
            printf("[Core] ❌ 嚴重錯誤：無法開啟 /dev/urandom 產生亂數\n");
            close(client_socket);
            close(server_fd);
            return -1;
        }

        // 每次從這台亂數產生機「讀取 1 單位 (共 16 bytes)」的資料，直接寫入 packet.rand
        fread(packet.rand, 1, 16, fp);
        fclose(fp); // 讀完記得關閉檔案

        //  (選用) 把每次產生的 RAND 印出來，方便你觀察每次連線的不同
        printf("[Core] 產生全新隨機 RAND: ");
        for(int i = 0; i < 16; i++) {
            printf("%02X", packet.rand[i]);
        }
        printf("\n");

        // 3. 呼叫 milenage 產生 AUTN, XRES, CK, IK
        uint8_t xres[8], ck[16], ik[16], xres_star[16];
        milenage_generate(core_config.opc, core_config.amf, core_config.k, core_config.sqn, packet.rand, packet.autn, ik, ck, xres);

        // 算成 5G XRES* 存起來等一下批改用
        calculate_res_star(ck, ik, core_config.snn, packet.rand, xres, xres_star);

        // 4. 發送挑戰題 (RAND + AUTN)
        packet.msg_type = MSG_AUTH_CHALLENGE;
        send(client_socket, &packet, sizeof(AuthPacket), 0);
        printf("[Core] 已發送 Challenge (RAND + AUTN)\n");

        // 5. 等待收卷
        recv(client_socket, &packet, sizeof(AuthPacket), 0);
        if (packet.msg_type == MSG_AUTH_RESPONSE) {
            printf("[Core] 收到 UE 答案，開始批改...\n");
            
            // 6. 比對 XRES* 與 UE 傳來的 RES*
            if (memcmp(xres_star, packet.res_star, 16) == 0) {
                printf("[Core] ⭕ 認證成功！RES* 完全吻合。\n");
                packet.auth_status = 1;
            } else {
                printf("[Core] ❌ 認證失敗！密碼不符。\n");
                packet.auth_status = 0;
            }
            
            // 發送最終結果
            packet.msg_type = MSG_AUTH_RESULT;
            send(client_socket, &packet, sizeof(AuthPacket), 0);
        }
    }

    close(client_socket);
    close(server_fd);
    return 0;
}