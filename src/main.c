/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata.h"
#include "conf.h"
#include "util-debug.h"
#ifdef HAVE_ONNXRUNTIME
#include "prefilter/onnx_interface.h"
#endif

int main(int argc, char **argv)
{
    /* Pre-initialization tasks: initialize global context and variables. */
    SuricataPreInit(argv[0]);

#ifdef OS_WIN32
    /* service initialization */
    if (WindowsInitService(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

    if (SCParseCommandLine(argc, argv) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    switch (SCStartInternalRunMode(argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    /* Load yaml configuration file if provided. */
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

#ifdef HAVE_ONNXRUNTIME
    // Инициализация ONNX модели из конфига
    const char* model_path = SCConfGet("prefilter.onnx-model", NULL);
    if (model_path == NULL) {
        SCLogError("ONNX model path not specified in configuration (prefilter.onnx-model)");
        exit(EXIT_FAILURE);
    }
    const char* input_dim_str = SCConfGet("prefilter.input-dim", NULL);
    size_t input_dim = 16;  // по умолчанию
    if (input_dim_str != NULL) {
        input_dim = atoi(input_dim_str);
    }
    if (OnnxInit(model_path, input_dim) != 0) {
        SCLogError("Failed to initialize ONNX model");
        exit(EXIT_FAILURE);
    }
#endif

    /* Enable default signal handlers */
    SCEnableDefaultSignalHandlers();

    /* Initialization tasks: apply configuration, drop privileges,
     * etc. */
    SuricataInit();

    /* Post-initialization tasks: wait on thread start/running and get ready for the main loop. */
    SuricataPostInit();

    SuricataMainLoop();

    /* Shutdown engine. */
    SuricataShutdown();
    GlobalsDestroy();

    // Print timing summary
    printf("\n=== Suricata Timing Summary ===\n");
    long long total_measured = g_decode_ethernet_total + g_app_layer_parser_total + g_detect_run_total +
                               g_detect_flow_total + g_flow_worker_total + g_detect_prefilter_total +
                               g_flow_worker_stream_tcp_update_total;
    printf("Total Measured Time: %lld ns\n\n", total_measured);

    // Exclusive times (subtracting measured child function times)
    long long detect_run_excl = g_detect_run_total - g_detect_prefilter_total;
    long long detect_flow_excl = g_detect_flow_total - g_detect_run_total;
    long long flow_worker_excl = g_flow_worker_total - g_detect_flow_total - g_flow_worker_stream_tcp_update_total;

    printf("Function Groups and Hierarchies (based on flame graph analysis):\n");
    printf("- Packet Decoding and Flow Management: DecodeEthernet, FlowWorker, DetectFlow\n");
    printf("- Detection Engine and Prefiltering: DetectRun, DetectRunPrefilterPkt\n");
    printf("- Stream and TCP Reassembly: FlowWorkerStreamTCPUpdate\n");
    printf("- Application Layer Parsing: AppLayerParserParse\n\n");

    // Group 1: Packet Decoding and Flow Management
    long long group1_total = g_decode_ethernet_total + g_flow_worker_total + g_detect_flow_total;
    double group1_pct = (double)group1_total / total_measured * 100.0;
    printf("Group 1: Packet Decoding and Flow Management - Total %lld ns (%.2f%%)\n", group1_total, group1_pct);
    if (g_decode_ethernet_count > 0) {
        double pct = (double)g_decode_ethernet_total / total_measured * 100.0;
        printf("  - Packet Decoding (DecodeEthernet): Total %lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_decode_ethernet_total, pct, g_decode_ethernet_count,
               (double)g_decode_ethernet_total / g_decode_ethernet_count);
    } else {
        printf("  - Packet Decoding (DecodeEthernet): No calls\n");
    }
    if (g_flow_worker_count > 0) {
        double pct = (double)g_flow_worker_total / total_measured * 100.0;
        double pct_excl = (double)flow_worker_excl / total_measured * 100.0;
        printf("  - Flow Worker (FlowWorker): Total %lld ns (%.2f%%), Exclusive ~%lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_flow_worker_total, pct, flow_worker_excl, pct_excl, g_flow_worker_count,
               (double)g_flow_worker_total / g_flow_worker_count);
    } else {
        printf("  - Flow Worker (FlowWorker): No calls\n");
    }
    if (g_detect_flow_count > 0) {
        double pct = (double)g_detect_flow_total / total_measured * 100.0;
        double pct_excl = (double)detect_flow_excl / total_measured * 100.0;
        printf("  - Detection Flow (DetectFlow): Total %lld ns (%.2f%%), Exclusive ~%lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_detect_flow_total, pct, detect_flow_excl, pct_excl, g_detect_flow_count,
               (double)g_detect_flow_total / g_detect_flow_count);
    } else {
        printf("  - Detection Flow (DetectFlow): No calls\n");
    }
    printf("\n");

    // Group 2: Detection Engine and Prefiltering
    long long group2_total = g_detect_run_total + g_detect_prefilter_total;
    double group2_pct = (double)group2_total / total_measured * 100.0;
    printf("Group 2: Detection Engine and Prefiltering - Total %lld ns (%.2f%%)\n", group2_total, group2_pct);
    if (g_detect_run_count > 0) {
        double pct = (double)g_detect_run_total / total_measured * 100.0;
        double pct_excl = (double)detect_run_excl / total_measured * 100.0;
        printf("  - Detection Core (DetectRun): Total %lld ns (%.2f%%), Exclusive ~%lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_detect_run_total, pct, detect_run_excl, pct_excl, g_detect_run_count,
               (double)g_detect_run_total / g_detect_run_count);
    } else {
        printf("  - Detection Core (DetectRun): No calls\n");
    }
    if (g_detect_prefilter_count > 0) {
        double pct = (double)g_detect_prefilter_total / total_measured * 100.0;
        printf("  - Prefiltering (DetectRunPrefilterPkt): Total %lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_detect_prefilter_total, pct, g_detect_prefilter_count,
               (double)g_detect_prefilter_total / g_detect_prefilter_count);
    } else {
        printf("  - Prefiltering (DetectRunPrefilterPkt): No calls\n");
    }
    printf("\n");

    // Group 3: Stream and TCP Reassembly
    long long group3_total = g_flow_worker_stream_tcp_update_total;
    double group3_pct = (double)group3_total / total_measured * 100.0;
    printf("Group 3: Stream and TCP Reassembly - Total %lld ns (%.2f%%)\n", group3_total, group3_pct);
    if (g_flow_worker_stream_tcp_update_count > 0) {
        double pct = (double)g_flow_worker_stream_tcp_update_total / total_measured * 100.0;
        printf("  - Stream TCP Update (FlowWorkerStreamTCPUpdate): Total %lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_flow_worker_stream_tcp_update_total, pct, g_flow_worker_stream_tcp_update_count,
               (double)g_flow_worker_stream_tcp_update_total / g_flow_worker_stream_tcp_update_count);
    } else {
        printf("  - Stream TCP Update (FlowWorkerStreamTCPUpdate): No calls\n");
    }
    printf("\n");

    // Group 4: Application Layer Parsing
    long long group4_total = g_app_layer_parser_total;
    double group4_pct = (double)group4_total / total_measured * 100.0;
    printf("Group 4: Application Layer Parsing - Total %lld ns (%.2f%%)\n", group4_total, group4_pct);
    if (g_app_layer_parser_count > 0) {
        double pct = (double)g_app_layer_parser_total / total_measured * 100.0;
        printf("  - App Layer Processing (AppLayerParserParse): Total %lld ns (%.2f%%), Count %d, Average %.2f ns\n",
               g_app_layer_parser_total, pct, g_app_layer_parser_count,
               (double)g_app_layer_parser_total / g_app_layer_parser_count);
    } else {
        printf("  - App Layer Processing (AppLayerParserParse): No calls\n");
    }
    printf("\n");
    printf("================================\n\n");

#ifdef HAVE_ONNXRUNTIME
    OnnxCleanup();
#endif

    exit(EXIT_SUCCESS);
}
