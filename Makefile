#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************
ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APPNAME    = "U2F Prober" 

APP_LOAD_PARAMS=--path "5583430'" --curve prime256r1 --appFlags 0x40 $(COMMON_LOAD_PARAMS)

APPVERSION_M=1
APPVERSION_N=2
APPVERSION_P=1
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

#prepare hsm generation
ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME=app_fido.gif
else
ICONNAME=icon.gif
endif

################
# Default rule #
################

all: default

############
# Platform #
############

#DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES   += HAVE_BAGL HAVE_SPRINTF
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64
ifneq ($(TARGET_NAME),TARGET_NANOS)
DEFINES   += HAVE_BLE HAVE_BLUENRG HCI_READ_PACKET_NUM_MAX=3 BLUENRG_MS HCI_READ_PACKET_SIZE=72
#DEFINES   += HAVE_BLE_APDU
endif
# Extra negative tests for interoperability tests
DEFINES	  += HAVE_TEST_INTEROP
# Derive on the same path as Johoe, disabled for speed (500 ms BLE timeout enforced)  
#DEFINES   += DERIVE_JOHOE
# Vierzon production U2F Token for probers
#DEFINES   += HAVE_VID_PID_PROBER HAVE_NO_USER_PRESENCE_CHECK

DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20
DEFINES   += U2F_MAX_MESSAGE_SIZE=768
DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

##############
# Compiler #
##############
#GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
#CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
CC       := $(CLANGPATH)clang 

#CFLAGS   += -O0
CFLAGS   += -O3 -Os

AS     := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc 

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### computed variables
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb 
ifneq ($(TARGET_NAME),TARGET_NANOS)
SDK_SOURCE_PATH  += lib_bluenrg
endif


load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile
