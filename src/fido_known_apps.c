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

#include <string.h>

#include "os.h"

typedef struct {
    unsigned char sha256[32];
    const char *name;
} fido_known_appid_t;

static const fido_known_appid_t fido_known_appid[] = {
    {// apple.com
     {0x22, 0x65, 0xcb, 0xcc, 0x3e, 0xf2, 0x41, 0x06, 0xc9, 0xe0, 0xed,
      0xdb, 0xd0, 0x4f, 0x3c, 0xca, 0x0d, 0x03, 0x22, 0x5d, 0xa3, 0xfc,
      0xca, 0x8e, 0x2d, 0x86, 0xf7, 0xa3, 0x94, 0xaf, 0x92, 0x83},
     "Apple"},
    {// aws.amazon.com
     {0x47, 0x41, 0x97, 0x9b, 0x08, 0xa6, 0x15, 0x2f, 0xd0, 0x14, 0x70,
      0x14, 0xce, 0x17, 0x21, 0xed, 0x7c, 0x93, 0x6c, 0x0f, 0xb2, 0xbe,
      0x2d, 0x69, 0x08, 0xa7, 0x2b, 0x73, 0x19, 0x52, 0xb0, 0x78},
     "Amazon"},
    {// binance.com
     {0x20, 0xf6, 0x61, 0xb1, 0x94, 0x0c, 0x34, 0x70, 0xac, 0x54, 0xfa,
      0x2e, 0xb4, 0x99, 0x90, 0xfd, 0x33, 0xb5, 0x6d, 0xe8, 0xde, 0x60,
      0x18, 0x70, 0xff, 0x02, 0xa8, 0x06, 0x0f, 0x3b, 0x7c, 0x58},
     "Binance"},
    {// U2F: www.binance.com
     {0xc3, 0x40, 0x8c, 0x04, 0x47, 0x88, 0xae, 0xa5, 0xb3, 0xdf, 0x30,
      0x89, 0x52, 0xfd, 0x8c, 0xa3, 0xc7, 0x0e, 0x21, 0xfe, 0xf4, 0xf6,
      0xc1, 0xc2, 0x37, 0x4c, 0xaa, 0x1d, 0xf9, 0xb2, 0x8d, 0xdd},
     "Binance"},
    {// U2F: https://bitbucket.org
     {0x12, 0x74, 0x3b, 0x92, 0x12, 0x97, 0xb7, 0x7f, 0x11, 0x35, 0xe4,
      0x1f, 0xde, 0xdd, 0x4a, 0x84, 0x6a, 0xfe, 0x82, 0xe1, 0xf3, 0x69,
      0x32, 0xa9, 0x91, 0x2f, 0x3b, 0x0d, 0x8d, 0xfb, 0x7d, 0x0e},
     "Bitbucket"},
    {// U2F: https://www.bitfinex.com
     {0x30, 0x2f, 0xd5, 0xb4, 0x49, 0x2a, 0x07, 0xb9, 0xfe, 0xbb, 0x30,
      0xe7, 0x32, 0x69, 0xec, 0xa5, 0x01, 0x20, 0x5c, 0xcf, 0xe0, 0xc2,
      0x0b, 0xf7, 0xb4, 0x72, 0xfa, 0x2d, 0x31, 0xe2, 0x1e, 0x63},
     "Bitfinex"},
    {// U2F: https://vault.bitwarden.com/app-id.json
     {0xa3, 0x4d, 0x30, 0x9f, 0xfa, 0x28, 0xc1, 0x24, 0x14, 0xb8, 0xba,
      0x6c, 0x07, 0xee, 0x1e, 0xfa, 0xe1, 0xa8, 0x5e, 0x8a, 0x04, 0x61,
      0x48, 0x59, 0xa6, 0x7c, 0x04, 0x93, 0xb6, 0x95, 0x61, 0x90},
     "Bitwarden"},
    {// U2F: coinbase.com
     {0xe2, 0x7d, 0x61, 0xb4, 0xe9, 0x9d, 0xe0, 0xed, 0x98, 0x16, 0x3c,
      0xb3, 0x8b, 0x7a, 0xf9, 0x33, 0xc6, 0x66, 0x5e, 0x55, 0x09, 0xe8,
      0x49, 0x08, 0x37, 0x05, 0x58, 0x13, 0x77, 0x8e, 0x23, 0x6a},
     "Coinbase"},
    {// U2F: https://www.dashlane.com
     {0x68, 0x20, 0x19, 0x15, 0xd7, 0x4c, 0xb4, 0x2a, 0xf5, 0xb3, 0xcc,
      0x5c, 0x95, 0xb9, 0x55, 0x3e, 0x3e, 0x3a, 0x83, 0xb4, 0xd2, 0xa9,
      0x3b, 0x45, 0xfb, 0xad, 0xaa, 0x84, 0x69, 0xff, 0x8e, 0x6e},
     "Dashlane"},
    {// U2F: https://www.dropbox.com/u2f-app-id.json
     {0xc5, 0x0f, 0x8a, 0x7b, 0x70, 0x8e, 0x92, 0xf8, 0x2e, 0x7a, 0x50,
      0xe2, 0xbd, 0xc5, 0x5d, 0x8f, 0xd9, 0x1a, 0x22, 0xfe, 0x6b, 0x29,
      0xc0, 0xcd, 0xf7, 0x80, 0x55, 0x30, 0x84, 0x2a, 0xf5, 0x81},
     "Dropbox"},
    {// WebAuthn: www.dropbox.com
     {0x82, 0xf4, 0xa8, 0xc9, 0x5f, 0xec, 0x94, 0xb2, 0x6b, 0xaf, 0x9e,
      0x37, 0x25, 0x0e, 0x95, 0x63, 0xd9, 0xa3, 0x66, 0xc7, 0xbe, 0x26,
      0x1c, 0xa4, 0xdd, 0x01, 0x01, 0xf4, 0xd5, 0xef, 0xcb, 0x83},
     "Dropbox"},
    {// U2F: https://api-9dcf9b83.duosecurity.com
     {0xf3, 0xe2, 0x04, 0x2f, 0x94, 0x60, 0x7d, 0xa0, 0xa9, 0xc1, 0xf3,
      0xb9, 0x5e, 0x0d, 0x2f, 0x2b, 0xb2, 0xe0, 0x69, 0xc5, 0xbb, 0x4f,
      0xa7, 0x64, 0xaf, 0xfa, 0x64, 0x7d, 0x84, 0x7b, 0x7e, 0xd6},
     "Duo"},
    {// facebook.com
     {0x31, 0x19, 0x33, 0x28, 0xf8, 0xe2, 0x1d, 0xfb, 0x6c, 0x99, 0xf3,
      0x22, 0xd2, 0x2d, 0x7b, 0x0b, 0x50, 0x87, 0x78, 0xe6, 0x4f, 0xfb,
      0xba, 0x86, 0xe5, 0x22, 0x93, 0x37, 0x90, 0x31, 0xb8, 0x74},
     "Facebook"},
    {// U2F: https://www.fastmail.com
     {0x69, 0x66, 0xab, 0xe3, 0x67, 0x4e, 0xa2, 0xf5, 0x30, 0x79, 0xeb,
      0x71, 0x01, 0x97, 0x84, 0x8c, 0x9b, 0xe6, 0xf3, 0x63, 0x99, 0x2f,
      0xd0, 0x29, 0xe9, 0x89, 0x84, 0x47, 0xcb, 0x9f, 0x00, 0x84},
     "FastMail"},
    {// U2F: https://id.fedoraproject.org/u2f-origins.json
     {0x9d, 0x61, 0x44, 0x2f, 0x5c, 0xe1, 0x33, 0xbd, 0x46, 0x54, 0x4f,
      0xc4, 0x2f, 0x0a, 0x6d, 0x54, 0xc0, 0xde, 0xb8, 0x88, 0x40, 0xca,
      0xc2, 0xb6, 0xae, 0xfa, 0x65, 0x14, 0xf8, 0x93, 0x49, 0xe9},
     "Fedora"},
    {// U2F: https://account.gandi.net/api/u2f/trusted_facets.json
     {0xa4, 0xe2, 0x2d, 0xca, 0xfe, 0xa7, 0xe9, 0x0e, 0x12, 0x89, 0x50,
      0x11, 0x39, 0x89, 0xfc, 0x45, 0x97, 0x8d, 0xc9, 0xfb, 0x87, 0x76,
      0x75, 0x60, 0x51, 0x6c, 0x1c, 0x69, 0xdf, 0xdf, 0xd1, 0x96},
     "Gandi"},
    {// github.com
     {0x3a, 0xeb, 0x00, 0x24, 0x60, 0x38, 0x1c, 0x6f, 0x25, 0x8e, 0x83,
      0x95, 0xd3, 0x02, 0x6f, 0x57, 0x1f, 0x0d, 0x9a, 0x76, 0x48, 0x8d,
      0xcd, 0x83, 0x76, 0x39, 0xb1, 0x3a, 0xed, 0x31, 0x65, 0x60},
     "GitHub"},
    {// U2F: https://github.com/u2f/trusted_facets
     {0x70, 0x61, 0x7d, 0xfe, 0xd0, 0x65, 0x86, 0x3a, 0xf4, 0x7c, 0x15,
      0x55, 0x6c, 0x91, 0x79, 0x88, 0x80, 0x82, 0x8c, 0xc4, 0x07, 0xfd,
      0xf7, 0x0a, 0xe8, 0x50, 0x11, 0x56, 0x94, 0x65, 0xa0, 0x75},
     "GitHub"},
    {// U2F: https://gitlab.com
     {0xe7, 0xbe, 0x96, 0xa5, 0x1b, 0xd0, 0x19, 0x2a, 0x72, 0x84, 0x0d,
      0x2e, 0x59, 0x09, 0xf7, 0x2b, 0xa8, 0x2a, 0x2f, 0xe9, 0x3f, 0xaa,
      0x62, 0x4f, 0x03, 0x39, 0x6b, 0x30, 0xe4, 0x94, 0xc8, 0x04},
     "GitLab"},
    {// google.com
     {0xd4, 0xc9, 0xd9, 0x02, 0x73, 0x26, 0x27, 0x1a, 0x89, 0xce, 0x51,
      0xfc, 0xaf, 0x32, 0x8e, 0xd6, 0x73, 0xf1, 0x7b, 0xe3, 0x34, 0x69,
      0xff, 0x97, 0x9e, 0x8a, 0xb8, 0xdd, 0x50, 0x1e, 0x66, 0x4f},
     "Google"},
    {// U2F: https://www.gstatic.com/securitykey/origins.json
     {0xa5, 0x46, 0x72, 0xb2, 0x22, 0xc4, 0xcf, 0x95, 0xe1, 0x51, 0xed,
      0x8d, 0x4d, 0x3c, 0x76, 0x7a, 0x6c, 0xc3, 0x49, 0x43, 0x59, 0x43,
      0x79, 0x4e, 0x88, 0x4f, 0x3d, 0x02, 0x3a, 0x82, 0x29, 0xfd},
     "Google"},
    {// U2F: https://keepersecurity.com
     {0x53, 0xa1, 0x5b, 0xa4, 0x2a, 0x7c, 0x03, 0x25, 0xb8, 0xdb, 0xee,
      0x28, 0x96, 0x34, 0xa4, 0x8f, 0x58, 0xae, 0xa3, 0x24, 0x66, 0x45,
      0xd5, 0xff, 0x41, 0x8f, 0x9b, 0xb8, 0x81, 0x98, 0x85, 0xa9},
     "Keeper"},
    {// kraken.com
     {0x3f, 0x37, 0x50, 0x85, 0x33, 0x2c, 0xac, 0x4f, 0xad, 0xf9, 0xe5,
      0xdd, 0x28, 0xcd, 0x54, 0x69, 0x8f, 0xab, 0x98, 0x4b, 0x75, 0xd9,
      0xc3, 0x6a, 0x07, 0x2c, 0xb1, 0x60, 0x77, 0x3f, 0x91, 0x52},
     "Kraken"},
    {// U2F: https://lastpass.com
     {0xd7, 0x55, 0xc5, 0x27, 0xa8, 0x6b, 0xf7, 0x84, 0x45, 0xc2, 0x82,
      0xe7, 0x13, 0xdc, 0xb8, 0x6d, 0x46, 0xff, 0x8b, 0x3c, 0xaf, 0xcf,
      0xb7, 0x3b, 0x2e, 0x8c, 0xbe, 0x6c, 0x08, 0x84, 0xcb, 0x24},
     "LastPass"},
    {// login.microsoft.com
     {0x35, 0x6c, 0x9e, 0xd4, 0xa0, 0x93, 0x21, 0xb9, 0x69, 0x5f, 0x1e,
      0xaf, 0x91, 0x82, 0x03, 0xf1, 0xb5, 0x5f, 0x68, 0x9d, 0xa6, 0x1f,
      0xbc, 0x96, 0x18, 0x4c, 0x15, 0x7d, 0xda, 0x68, 0x0c, 0x81},
     "Microsoft"},
    {// U2F: https://slushpool.com/static/security/u2f.json
     {0x08, 0xb2, 0xa3, 0xd4, 0x19, 0x39, 0xaa, 0x31, 0x66, 0x84, 0x93,
      0xcb, 0x36, 0xcd, 0xcc, 0x4f, 0x16, 0xc4, 0xd9, 0xb4, 0xc8, 0x23,
      0x8b, 0x73, 0xc2, 0xf6, 0x72, 0xc0, 0x33, 0x00, 0x71, 0x97},
     "Slush Pool"},
    {// U2F: https://dashboard.stripe.com
     {0x2a, 0xc6, 0xad, 0x09, 0xa6, 0xd0, 0x77, 0x2c, 0x44, 0xda, 0x73,
      0xa6, 0x07, 0x2f, 0x9d, 0x24, 0x0f, 0xc6, 0x85, 0x4a, 0x70, 0xd7,
      0x9c, 0x10, 0x24, 0xff, 0x7c, 0x75, 0x59, 0x59, 0x32, 0x92},
     "Stripe"},
    {// U2F: https://u2f.bin.coffee
     {0x1b, 0x3c, 0x16, 0xdd, 0x2f, 0x7c, 0x46, 0xe2, 0xb4, 0xc2, 0x89,
      0xdc, 0x16, 0x74, 0x6b, 0xcc, 0x60, 0xdf, 0xcf, 0x0f, 0xb8, 0x18,
      0xe1, 0x32, 0x15, 0x52, 0x6e, 0x14, 0x08, 0xe7, 0xf4, 0x68},
     "u2f.bin.coffee"},
    {// WebAuthn: webauthn.bin.coffee
     {0xa6, 0x42, 0xd2, 0x1b, 0x7c, 0x6d, 0x55, 0xe1, 0xce, 0x23, 0xc5,
      0x39, 0x98, 0x28, 0xd2, 0xc7, 0x49, 0xbf, 0x6a, 0x6e, 0xf2, 0xfe,
      0x03, 0xcc, 0x9e, 0x10, 0xcd, 0xf4, 0xed, 0x53, 0x08, 0x8b},
     "webauthn.bin.coffee"},
    {// WebAuthn: webauthn.io
     {0x74, 0xa6, 0xea, 0x92, 0x13, 0xc9, 0x9c, 0x2f, 0x74, 0xb2, 0x24,
      0x92, 0xb3, 0x20, 0xcf, 0x40, 0x26, 0x2a, 0x94, 0xc1, 0xa9, 0x50,
      0xa0, 0x39, 0x7f, 0x29, 0x25, 0x0b, 0x60, 0x84, 0x1e, 0xf0},
     "WebAuthn.io"},
    {// WebAuthn: webauthn.me
     {0xf9, 0x5b, 0xc7, 0x38, 0x28, 0xee, 0x21, 0x0f, 0x9f, 0xd3, 0xbb,
      0xe7, 0x2d, 0x97, 0x90, 0x80, 0x13, 0xb0, 0xa3, 0x75, 0x9e, 0x9a,
      0xea, 0x3d, 0x0a, 0xe3, 0x18, 0x76, 0x6c, 0xd2, 0xe1, 0xad},
     "WebAuthn.me"},
    {// WebAuthn: demo.yubico.com
     {0xc4, 0x6c, 0xef, 0x82, 0xad, 0x1b, 0x54, 0x64, 0x77, 0x59, 0x1d,
      0x00, 0x8b, 0x08, 0x75, 0x9e, 0xc3, 0xe6, 0xd2, 0xec, 0xb4, 0xf3,
      0x94, 0x74, 0xbf, 0xea, 0x69, 0x69, 0x92, 0x5d, 0x03, 0xb7},
     "demo.yubico.com"},
};

const char *fido_match_known_appid(const uint8_t *applicationParameter) {
    unsigned int i;
    for (i = 0; i < sizeof(fido_known_appid) / sizeof(fido_known_appid[0]); i++) {
        if (memcmp(applicationParameter, fido_known_appid[i].sha256, 32) == 0) {
            return (const char *) PIC(fido_known_appid[i].name);
        }
    }
    return NULL;
}
