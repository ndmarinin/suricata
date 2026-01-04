#include <iostream>
#include <vector>
#include <onnxruntime_cxx_api.h>  // Требуется ONNX Runtime
#include <stdexcept>

class ONNXModel {
public:
    ONNXModel(const std::string& model_path, size_t input_dim)
        : env_(ORT_LOGGING_LEVEL_WARNING, "suricata_prefilter"),
          session_(nullptr),
          input_dim_(input_dim)
    {
        Ort::SessionOptions session_options;
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        session_ = Ort::Session(env_, model_path.c_str(), session_options);

        allocator_ = Ort::AllocatorWithDefaultOptions();
        input_name_ = session_.GetInputName(0, allocator_);
        output_name_ = session_.GetOutputName(0, allocator_);
    }

    int predict(const std::vector<float>& input_features) {
        if (input_features.size() != input_dim_) {
            throw std::invalid_argument("Invalid input dimension.");
        }

        // Create input tensor
        std::array<int64_t, 2> input_shape{1, static_cast<int64_t>(input_dim_)};
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            allocator_.GetInfo(),
            const_cast<float*>(input_features.data()),
            input_features.size() * sizeof(float),
            input_shape.data(),
            input_shape.size()
        );

        // Run inference
        auto output_tensors = session_.Run(
            Ort::RunOptions{nullptr},
            &input_name_, &input_tensor, 1,
            &output_name_, 1
        );

        float* result = output_tensors[0].GetTensorMutableData<float>();
        return static_cast<int>(result[0] >= 0.5f);  // Порог по умолчанию 0.5
    }

private:
    Ort::Env env_;
    Ort::Session session_;
    Ort::AllocatorWithDefaultOptions allocator_;
    const char* input_name_;
    const char* output_name_;
    size_t input_dim_;
};
