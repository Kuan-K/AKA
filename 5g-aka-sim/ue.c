#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"
#include "milenage.h"

// 寫死 UE 端的金鑰資料 (必須跟 Core 一模一樣才能認證成功)
AkaConfig ue_config = {
    .k   = {0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC},
    .opc = {0xE8, 0xED, 0x28, 0x9D, 0xEB, 0xA9, 0x52, 0xE4, 0x28, 0x3B, 0x54, 0xE8, 0x8E, 0x61, 0x83, 0xCA},
    .sqn = {0x00, 0x00, 0x00, 0x00, 0x00, 0x20}, // 假設計數器兩邊一致
    .amf = {0x80, 0x00},
    .snn = "5G:mnc092.mcc466.3gppnetwork.org"
};

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    AuthPacket packet;

    // 1. 連線到 Core
    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[UE] 連線失敗，請先啟動 Core 端程式。\n");
        return -1;
    }
    printf("[UE] 成功連上 Core 網路！\n");

    // 2. 觸發認證
    packet.msg_type = MSG_AUTH_TRIGGER;
    send(sock, &packet, sizeof(AuthPacket), 0);

    // 3. 收到 Challenge
    recv(sock, &packet, sizeof(AuthPacket), 0);
    if (packet.msg_type == MSG_AUTH_CHALLENGE) {
        printf("[UE] 收到 Challenge，開始解題...\n");

        uint8_t res[8], ck[16], ik[16], ak[6], my_mac[8];
        
        // 【補足 OAI 的缺陷】：取出 AUTN 裡的 MAC 進行防偽驗證
        uint8_t received_mac[8];
        memcpy(received_mac, packet.autn + 8, 8);
        
        // 取得 AK 來解開 SQN
        milenage_f2345(ue_config.opc, ue_config.k, packet.rand, res, ck, ik, ak, NULL);
        
        uint8_t hidden_sqn[6];
        memcpy(hidden_sqn, packet.autn, 6);
        uint8_t real_sqn[6];
        for(int i=0; i<6; i++) real_sqn[i] = hidden_sqn[i] ^ ak[i]; // XOR 解碼 SQN

        // 用解開的 SQN 自己算一次 MAC
        milenage_f1(ue_config.opc, ue_config.k, packet.rand, real_sqn, ue_config.amf, my_mac, NULL);

        // 比對 MAC (驗證基地台真偽)
        if (memcmp(my_mac, received_mac, 8) != 0) {
            printf("[UE] ❌ 警告：MAC 驗證失敗！這是一個偽造的基地台！\n");
            // 實務上這裡會發送 Authentication Failure，為了簡化直接中斷
            close(sock);
            return -1;
        }
        printf("[UE] 網路 MAC 驗證通過，基地台為真。\n");

        // 4. 算成 5G RES* 準備交卷
        calculate_res_star(ck, ik, ue_config.snn, packet.rand, res, packet.res_star);
        
        packet.msg_type = MSG_AUTH_RESPONSE;
        send(sock, &packet, sizeof(AuthPacket), 0);
        printf("[UE] 已送出 RES* 答案。\n");

        // 5. 聽取結果
        recv(sock, &packet, sizeof(AuthPacket), 0);
        if (packet.auth_status == 1) {
            printf("[UE] 🎉 認證成功！允許上網。\n");
        } else {
            printf("[UE] ❌ 認證失敗！遭網路拒絕。\n");
        }
    }

    close(sock);
    return 0;
}