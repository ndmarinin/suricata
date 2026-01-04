#include "suricata-common.h"
#include "decode.h"
#include "flow.h"
#include "detect.h"
#include "onnx_interface.h"  // обёртка C для C++ класса

static int OnnxPrefilterFlowHook(const Packet *p, const Flow *f) {
    float features[16];

    // Преобразуем Flow в признаки (пример):
    features[0] = 0.0f;  // p->sp
    features[1] = 0.0f;  // p->dp
    features[2] = 0.0f;  // Длительность (placeholder, зависит от версии Suricata)
    features[15] = 0.0f;  // p->proto

    // Предсказание
    int result = OnnxPrefilterPredict(features, 16);
    return result; // 1 — подозрительный, 0 — безопасный
}
