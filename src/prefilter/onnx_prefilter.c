#include "suricata-common.h"
#include "decode.h"
#include "flow.h"
#include "detect.h"
#include "onnx_interface.h"  // обёртка C для C++ класса

int OnnxPrefilterFlowHook(const Packet *p, const Flow *f) {
    float features[16];

    // Преобразуем Flow в признаки (пример):
    features[0] = (float)p->sp;
    features[1] = (float)p->dp;
    features[2] = (float)((f->lastts.tv_sec * 1000000000LL + f->lastts.tv_nsec) - (f->startts.tv_sec * 1000000000LL + f->startts.tv_nsec)) / 1000000000.0f;  // Длительность в секундах
    features[15] = (float)p->proto;

    // Предсказание
    int result = OnnxPrefilterPredict(features, 16);
    return result; // 1 — подозрительный, 0 — безопасный
}
