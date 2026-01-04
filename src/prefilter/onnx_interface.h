#ifndef ONNX_INTERFACE_H
#define ONNX_INTERFACE_H

#include <stddef.h>

#ifndef __cplusplus
#include "decode.h"
#include "flow.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Инициализация модели ONNX
int OnnxInit(const char* model_path, size_t input_dim);

// Предсказание
int OnnxPrefilterPredict(float *features, size_t len);

// Освобождение ресурсов
void OnnxCleanup(void);

// Хук для prefilter
extern int OnnxPrefilterFlowHook(const Packet *p, const Flow *f);

#ifdef __cplusplus
}
#endif

#endif // ONNX_INTERFACE_H