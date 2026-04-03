#include <stdint.h>

// 定義通訊階段的訊息代碼 (MsgType)
typedef enum {
    MSG_AUTH_TRIGGER   = 1,  // UE -> Core: "哈囉，我要發起連線"
    MSG_AUTH_CHALLENGE = 2,  // Core -> UE:  "這是考卷 (包含 RAND 與 AUTN)"
    MSG_AUTH_RESPONSE  = 3,  // UE -> Core: "這是我算出的答案 (包含 RES*)"
    MSG_AUTH_RESULT    = 4   // Core -> UE:  "批改結果 (成功或失敗)"
} MsgType;

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
