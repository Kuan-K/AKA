#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// 定義通訊階段的訊息代碼
#define    MSG_AUTH_TRIGGER    1  // UE -> Core: "哈囉，我要發起連線"
#define    MSG_AUTH_CHALLENGE  2  // Core -> UE:  "這是考卷 (包含 RAND 與 AUTN)"
#define    MSG_AUTH_RESPONSE   3  // UE -> Core: "這是我算出的答案 (包含 RES*)"
#define    MSG_AUTH_RESULT     4  // Core -> UE:  "批改結果 (成功或失敗)"

// TCP 傳輸用的統一封包結構
typedef struct {
    int msg_type;            // 標示這包資料屬於哪個階段 (填入上面的 MsgType)
    
    // --- 來自 Core 的挑戰 (對應筆記的 input 與 output) ---
    uint8_t rand[16];        // 隨機碼 RAND (16 Bytes)
    uint8_t autn[16];        // 認證向量 AUTN (16 Bytes) 
                             // -> 筆記標示: SQN(6) + AMF(2) + MAC(8)

    // --- 來自 UE 的答案 ---
    uint8_t res_star[16];    // 經過 transferRES 計算出來的加強版答案 (16 Bytes)

    // --- 來自 Core 的批改結果 ---
    int auth_status;         // 認證狀態 (1 代表成功，0 代表失敗/MAC錯誤)
} AuthPacket;

// 內部使用的設定檔結構 (寫死在程式內)
typedef struct {
    uint8_t k[16];          
    uint8_t opc[16];        
    uint8_t sqn[6];         
    uint8_t amf[2];         
    char snn[64];           
} AkaConfig;

// 計算 5G RES* (等同於 OAI 的 transferRES)
void calculate_res_star(uint8_t *ck, uint8_t *ik, char *snn, uint8_t *rand_val, uint8_t *res, uint8_t *res_star) {
    uint8_t key[32];
    memcpy(key, ck, 16);
    memcpy(key + 16, ik, 16); // Key = CK || IK

    uint8_t S[100] = {0};
    int snn_len = strlen(snn);
    
    // 組裝 S 陣列
    S[0] = 0x6B; // FC
    memcpy(&S[1], snn, snn_len);
    S[1 + snn_len] = (snn_len & 0xff00) >> 8;
    S[2 + snn_len] = (snn_len & 0x00ff);
    memcpy(&S[3 + snn_len], rand_val, 16);
    S[19 + snn_len] = 0x00;
    S[20 + snn_len] = 0x10;
    memcpy(&S[21 + snn_len], res, 8);
    S[29 + snn_len] = 0x00;
    S[30 + snn_len] = 0x08;

    unsigned int out_len;
    uint8_t out[32];
    // 呼叫 OpenSSL 的 HMAC-SHA256
    HMAC(EVP_sha256(), key, 32, S, 31 + snn_len, out, &out_len);
    
    // 取最後 16 bytes 作為 RES*
    memcpy(res_star, out + 16, 16); 
}

#endif