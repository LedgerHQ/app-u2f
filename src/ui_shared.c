/*
*******************************************************************************
*   Ledger App FIDO U2F
*   (c) 2022 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include "ux.h"

#include "glyphs.h"
#include "ui_shared.h"

static void app_quit(void) {
#ifdef REVAMPED_IO
    // handle properly the USB stop/start
    os_io_stop();
#endif /* #ifdef REVAMPED_IO */
    // exit app here
    os_sched_exit(-1);
}

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_idle_flow_1_step,
             nn,
             {
                 "Ready to",
                 "authenticate",
             });
UX_STEP_NOCB(ux_idle_flow_2_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_CB(ux_idle_flow_3_step,
           pb,
           app_quit(),
           {
               &C_icon_dashboard,
               "Quit",
           });
UX_FLOW(ux_idle_flow, &ux_idle_flow_1_step, &ux_idle_flow_2_step, &ux_idle_flow_3_step);

void ui_idle(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    G_ux.externalText = NULL;
    ux_flow_init(0, ux_idle_flow, NULL);
}

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"

// 'About' menu

static const char* const INFO_TYPES[] = {"Version", "Copyright"};
static const char* const INFO_CONTENTS[] = {APPVERSION, "(c) 2023 Ledger"};

static bool nav_callback(uint8_t page, nbgl_pageContent_t* content) {
    UNUSED(page);
    content->type = INFOS_LIST;
    content->infosList.nbInfos = 2;
    content->infosList.infoTypes = (const char**) INFO_TYPES;
    content->infosList.infoContents = (const char**) INFO_CONTENTS;
    return true;
}

static void ui_menu_about() {
    nbgl_useCaseSettings(APPNAME, 0, 1, false, ui_idle, nav_callback, NULL);
}

void ui_idle(void) {
    nbgl_useCaseHome(APPNAME,
                     &C_stax_id_64px,
                     "This app enables using\nyour Ledger device for\nTwo Factor Authentication.",
                     false,
                     ui_menu_about,
                     app_quit);
}

#endif
