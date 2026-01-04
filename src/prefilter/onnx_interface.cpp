#include "onnx_interface.h"
#include "onnx_infer.cpp"  // Включаем C++ класс

static ONNXModel* model = nullptr;

extern "C" {

int OnnxInit(const char* model_path, size_t input_dim) {
    try {
        model = new ONNXModel(model_path, input_dim);
        return 0;  // Успех
    } catch (const std::exception& e) {
        return -1;  // Ошибка
    }
}

int OnnxPrefilterPredict(float *features, size_t len) {
    if (!model) return -1;
    std::vector<float> vec(features, features + len);
    try {
        return model->predict(vec);
    } catch (const std::exception& e) {
        return -1;
    }
}

void OnnxCleanup() {
    delete model;
    model = nullptr;
}

}