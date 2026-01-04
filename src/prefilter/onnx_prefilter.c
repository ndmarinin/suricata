#include "onnx_interface.h"  // обёртка C для C++ класса
#include "suricata-common.h"
#include "decode.h"
#include "flow.h"
#include "detect.h"

int OnnxPrefilterFlowHook(const Packet *p, const Flow *f) {
    float features[16];

    // Преобразуем Flow в признаки (пример):
    features[0] = (float)p->sp;
    features[1] = (float)p->dp;
    features[2] = (float)FlowGetAge(f) / 1000000000.0f;  // Длительность в секундах
    features[15] = (float)p->proto;

    // Предсказание
    int result = OnnxPrefilterPredict(features, 16);
    return result; // 1 — подозрительный, 0 — безопасный
}
