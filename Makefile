#******************************************************************************
#   Ledger App FIDO U2F
#   (c) 2022 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#   limitations under the License.
#*******************************************************************************/

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

$(info TARGET_NAME=$(TARGET_NAME))
ifneq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOS TARGET_NANOX TARGET_NANOS2 TARGET_STAX))
$(error Environment variable TARGET_NAME is not valid or not supported)
endif

APPNAME = "Fido U2F"

APP_LOAD_PARAMS  = --curve secp256r1
APP_LOAD_PARAMS += --path "5583430'"  # int("U2F".encode("ascii").hex(), 16)
APP_LOAD_PARAMS += --appFlags 0x040
APP_LOAD_PARAMS += $(COMMON_LOAD_PARAMS)

APPVERSION_M=1
APPVERSION_N=3
APPVERSION_P=0
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=icons/icon_id_nanos.gif
else ifeq ($(TARGET_NAME),TARGET_STAX)
ICONNAME=icons/stax_id_32px.gif
else
ICONNAME=icons/icon_id.gif
endif

################
# Default rule #
################

all: default

################
# Attestations #
################
PROD_U2F_NANOS_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOS_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOS_PRIVATE_KEY=${PROD_U2F_NANOS_PRIVATE_KEY}
endif

PROD_U2F_NANOX_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOX_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOX_PRIVATE_KEY=${PROD_U2F_NANOX_PRIVATE_KEY}
endif

PROD_U2F_NANOSP_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOSP_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOSP_PRIVATE_KEY=${PROD_U2F_NANOSP_PRIVATE_KEY}
endif

PROD_U2F_STAX_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_STAX_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_STAX_PRIVATE_KEY=${PROD_U2F_STAX_PRIVATE_KEY}
endif

############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

DEFINES += HAVE_U2F HAVE_IO_U2F
DEFINES += USB_SEGMENT_SIZE=64
DEFINES += CUSTOM_IO_APDU_BUFFER_SIZE=1031 # 1024 + 7
DEFINES += UNUSED\(x\)=\(void\)x
DEFINES += APPVERSION=\"$(APPVERSION)\"
CFLAGS  += -DAPPNAME=\"Fido\ U2F\"

ifneq ($(TARGET_NAME),TARGET_STAX)
DEFINES += HAVE_BAGL HAVE_UX_FLOW
endif

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
DEFINES += HAVE_GLO096
DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

# Enabling debug PRINTF
DEBUG=0
ifneq ($(DEBUG),0)
    ifeq ($(TARGET_NAME),TARGET_NANOX)
        DEFINES += HAVE_PRINTF PRINTF=mcu_usb_printf
    else
        DEFINES += HAVE_PRINTF PRINTF=screen_printf
    endif
else
        DEFINES += PRINTF\(...\)=
endif

DEFINES += HAVE_UX_STACK_INIT_KEEP_TICKER

###############
# Application #
###############

# Used to initialize app counter to current timestamp directly in the app bin code
# when the app is streamed from the HSM.
# This is necessary to never use the counter with a lower value than previous calls.
# This means that the app APDU will be patched when streamed from the HSM and therefore
# the apdu should not contain a crc.
DEFINES += HAVE_COUNTER_MARKER
APP_LOAD_PARAMS += --nocrc

# Used to disable user presence check.
# This is against U2F standard and should be used only for development purposes.
#DEFINES += HAVE_NO_USER_PRESENCE_CHECK

##############
# Compiler #
##############

WERROR=0
ifneq ($(WERROR),0)
    CFLAGS += -Werror
endif

CC      := $(CLANGPATH)clang
CFLAGS  += -O3 -Os
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

# Remove warning on custom snprintf implementation usage
CFLAGS += -Wno-format-invalid-specifier -Wno-format-extra-args

# Import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

# Define directory to build
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb lib_u2f lib_stusb_impl

ifneq ($(TARGET_NAME),TARGET_STAX)
SDK_SOURCE_PATH += lib_ux
endif

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# Import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

# Add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS NONE fido_u2f
