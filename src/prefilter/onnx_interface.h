#ifndef ONNX_INTERFACE_H
#define ONNX_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

// Инициализация модели ONNX
int OnnxInit(const char* model_path, size_t input_dim);

// Предсказание
int OnnxPrefilterPredict(float *features, size_t len);

// Освобождение ресурсов
void OnnxCleanup();

#ifdef __cplusplus
}
#endif

#endif // ONNX_INTERFACE_H