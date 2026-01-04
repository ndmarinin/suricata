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
#include "util-conf.h"
#include "util-debug.h"
#ifdef HAVE_ONNXRUNTIME
#include "prefilter/onnx_interface.h"
#endif

extern const char* ConfGet(const char*, const char*);

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
    const char* model_path = ConfGet("prefilter.onnx-model", NULL);
    if (model_path == NULL) {
        SCLogError("ONNX model path not specified in configuration (prefilter.onnx-model)");
        exit(EXIT_FAILURE);
    }
    const char* input_dim_str = ConfGet("prefilter.input-dim", NULL);
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

#ifdef HAVE_ONNXRUNTIME
    OnnxCleanup();
#endif

    exit(EXIT_SUCCESS);
}
