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
    if (g_decode_ethernet_count > 0) {
        printf("Packet Parsing (DecodeEthernet): Total %lld ns, Count %d, Average %.2f ns\n",
               g_decode_ethernet_total, g_decode_ethernet_count,
               (double)g_decode_ethernet_total / g_decode_ethernet_count);
    } else {
        printf("Packet Parsing (DecodeEthernet): No calls\n");
    }
    if (g_app_layer_parser_count > 0) {
        printf("Data Management/App-Layer Parsing (AppLayerParserParse): Total %lld ns, Count %d, Average %.2f ns\n",
               g_app_layer_parser_total, g_app_layer_parser_count,
               (double)g_app_layer_parser_total / g_app_layer_parser_count);
    } else {
        printf("Data Management/App-Layer Parsing (AppLayerParserParse): No calls\n");
    }
    if (g_detect_run_count > 0) {
        printf("Threat Detection (DetectRun): Total %lld ns, Count %d, Average %.2f ns\n",
               g_detect_run_total, g_detect_run_count,
               (double)g_detect_run_total / g_detect_run_count);
    } else {
        printf("Threat Detection (DetectRun): No calls\n");
    }
    printf("================================\n\n");

    exit(EXIT_SUCCESS);
}
