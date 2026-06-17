/*
 * CareFortress Windows Log Agent
 * Native Win32 service for Windows XP SP3, XP Embedded, and Windows CE
 *
 * Discovers the virtio-serial COM port via registry query and writes
 * structured JSON log entries to the channel.
 *
 * Build (MinGW on Linux cross-compile):
 *   x86_64-w64-mingw32-gcc -o agent_windows.exe agent_windows.c \
 *     -ladvapi32 -lkernel32 -static
 *
 * Build (MSVC on Windows):
 *   cl agent_windows.c /link advapi32.lib kernel32.lib
 *
 * Install:
 *   agent_windows.exe install
 *   sc start CareFortressAgent
 *
 * Uninstall:
 *   sc stop CareFortressAgent
 *   agent_windows.exe uninstall
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SERVICE_NAME        "CareFortressAgent"
#define SERVICE_DISPLAY     "CareFortress Log Agent"
#define SERVICE_DESC        "CareFortress hypervisor audit logging agent"
#define CHANNEL_NAME        "log.medical-vm"
#define HEARTBEAT_INTERVAL  30  /* seconds */
#define COM_PORT_BUFSIZE    32
#define JSON_BUFSIZE        1024
#define REGISTRY_PATH       "SYSTEM\\CurrentControlSet\\Enum"

/* Global service state */
static SERVICE_STATUS        g_svc_status;
static SERVICE_STATUS_HANDLE g_svc_status_handle;
static HANDLE                g_stop_event = NULL;
static HANDLE                g_com_handle = INVALID_HANDLE_VALUE;
static char                  g_com_port[COM_PORT_BUFSIZE] = {0};
static unsigned long         g_entry_count = 0;
static char                  g_prev_hash[65] = {0};

/* ── SHA-256 (public domain implementation) ─────────────────────────── */
typedef unsigned char  uint8;
typedef unsigned int   uint32;
typedef unsigned long long uint64;

typedef struct { uint8 data[64]; uint32 datalen; uint64 bitlen; uint32 state[8]; } SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32 k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8 *data) {
    uint32 a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for(i=0,j=0;i<16;++i,j+=4) m[i]=((uint32)data[j]<<24)|((uint32)data[j+1]<<16)|((uint32)data[j+2]<<8)|((uint32)data[j+3]);
    for(;i<64;++i) m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for(i=0;i<64;++i){
        t1=h+EP1(e)+CH(e,f,g)+k[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}
static void sha256_init(SHA256_CTX *ctx){
    ctx->datalen=0;ctx->bitlen=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}
static void sha256_update(SHA256_CTX *ctx, const uint8 *data, size_t len){
    uint32 i;
    for(i=0;i<len;++i){
        ctx->data[ctx->datalen]=data[i];
        if(++ctx->datalen==64){sha256_transform(ctx,ctx->data);ctx->bitlen+=512;ctx->datalen=0;}
    }
}
static void sha256_final(SHA256_CTX *ctx, uint8 *hash){
    uint32 i=ctx->datalen;
    if(ctx->datalen<56){ctx->data[i++]=0x80;while(i<56)ctx->data[i++]=0x00;}
    else{ctx->data[i++]=0x80;while(i<64)ctx->data[i++]=0x00;sha256_transform(ctx,ctx->data);memset(ctx->data,0,56);}
    ctx->bitlen+=ctx->datalen*8;
    ctx->data[63]=ctx->bitlen;ctx->data[62]=ctx->bitlen>>8;ctx->data[61]=ctx->bitlen>>16;ctx->data[60]=ctx->bitlen>>24;
    ctx->data[59]=ctx->bitlen>>32;ctx->data[58]=ctx->bitlen>>40;ctx->data[57]=ctx->bitlen>>48;ctx->data[56]=ctx->bitlen>>56;
    sha256_transform(ctx,ctx->data);
    for(i=0;i<4;++i){
        hash[i]   =(ctx->state[0]>>(24-i*8))&0xff; hash[i+4] =(ctx->state[1]>>(24-i*8))&0xff;
        hash[i+8] =(ctx->state[2]>>(24-i*8))&0xff; hash[i+12]=(ctx->state[3]>>(24-i*8))&0xff;
        hash[i+16]=(ctx->state[4]>>(24-i*8))&0xff; hash[i+20]=(ctx->state[5]>>(24-i*8))&0xff;
        hash[i+24]=(ctx->state[6]>>(24-i*8))&0xff; hash[i+28]=(ctx->state[7]>>(24-i*8))&0xff;
    }
}

static void compute_sha256_hex(const char *input, char *out_hex) {
    SHA256_CTX ctx;
    uint8 hash[32];
    int i;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8*)input, strlen(input));
    sha256_final(&ctx, hash);
    for(i=0;i<32;i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
}

/* ── ISO 8601 timestamp ─────────────────────────────────────────────── */
static void get_iso8601(char *buf, size_t bufsize) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    snprintf(buf, bufsize, "%04d-%02d-%02dT%02d:%02d:%02d.000000+00:00",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

/* ── COM port discovery via registry ────────────────────────────────── */
static int find_virtio_serial_port(char *port_out, size_t port_bufsize) {
    /*
     * Walk HKLM\SYSTEM\CurrentControlSet\Enum looking for a device
     * with FriendlyName containing the CHANNEL_NAME string.
     * On Windows XP, virtio-serial devices enumerate under VirtIO or
     * as standard serial ports with the channel name as friendly name.
     * Fallback: try COM3 through COM9.
     */
    HKEY hKey, hSubKey, hSubSubKey;
    char subkey[256], subsubkey[256], portname[32], friendly[256];
    DWORD subkey_len, friendly_len, portname_len, type;
    LONG ret;
    int found = 0;

    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_PATH, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) goto fallback;

    for (DWORD i = 0; !found; i++) {
        subkey_len = sizeof(subkey);
        ret = RegEnumKeyEx(hKey, i, subkey, &subkey_len, NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;

        if (RegOpenKeyEx(hKey, subkey, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) continue;

        for (DWORD j = 0; !found; j++) {
            subsubkey[0] = '\0';
            DWORD subsubkey_len = sizeof(subsubkey);
            ret = RegEnumKeyEx(hSubKey, j, subsubkey, &subsubkey_len, NULL, NULL, NULL, NULL);
            if (ret == ERROR_NO_MORE_ITEMS) break;
            if (ret != ERROR_SUCCESS) continue;

            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s\\%s\\%s\\Device Parameters",
                     REGISTRY_PATH, subkey, subsubkey);

            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, full_path, 0, KEY_READ, &hSubSubKey) != ERROR_SUCCESS) continue;

            friendly_len = sizeof(friendly);
            portname_len = sizeof(portname);

            RegQueryValueEx(hSubSubKey, "PortName", NULL, &type, (LPBYTE)portname, &portname_len);
            RegCloseKey(hSubSubKey);

            /* Check parent for FriendlyName containing channel name */
            char parent_path[512];
            snprintf(parent_path, sizeof(parent_path), "%s\\%s\\%s",
                     REGISTRY_PATH, subkey, subsubkey);
            HKEY hParent;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, parent_path, 0, KEY_READ, &hParent) == ERROR_SUCCESS) {
                friendly_len = sizeof(friendly);
                if (RegQueryValueEx(hParent, "FriendlyName", NULL, &type,
                                    (LPBYTE)friendly, &friendly_len) == ERROR_SUCCESS) {
                    if (strstr(friendly, CHANNEL_NAME) && portname[0]) {
                        snprintf(port_out, port_bufsize, "\\\\.\\%s", portname);
                        found = 1;
                    }
                }
                RegCloseKey(hParent);
            }
        }
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hKey);

fallback:
    if (!found) {
        /* Try COM3-COM9 as fallback */
        for (int p = 3; p <= 9 && !found; p++) {
            char try_port[32];
            snprintf(try_port, sizeof(try_port), "\\\\.\\COM%d", p);
            HANDLE h = CreateFile(try_port, GENERIC_WRITE, 0, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
                snprintf(port_out, port_bufsize, "%s", try_port);
                found = 1;
            }
        }
    }
    return found;
}

/* ── Write JSON entry to COM port ──────────────────────────────────── */
static int write_entry(const char *event_type, const char *msg) {
    char ts[64], json[JSON_BUFSIZE], hash_input[JSON_BUFSIZE + 65], new_hash[65];
    DWORD written;

    if (g_com_handle == INVALID_HANDLE_VALUE) return 0;

    get_iso8601(ts, sizeof(ts));

    /* Build JSON payload */
    snprintf(json, sizeof(json),
             "{\"ts\":\"%s\",\"host\":\"windows-agent\","
             "\"type\":\"%s\",\"msg\":\"%s\","
             "\"entry\":%lu}",
             ts, event_type, msg, g_entry_count);

    /* Compute chain hash */
    snprintf(hash_input, sizeof(hash_input), "%s%s", g_prev_hash, json);
    compute_sha256_hex(hash_input, new_hash);

    /* Build chained entry */
    char entry[JSON_BUFSIZE + 200];
    snprintf(entry, sizeof(entry),
             "{\"collected_ts\":\"%s\",\"source_vm\":\"windows-agent\","
             "\"payload\":%s,\"prev_hash\":\"%s\","
             "\"chain_hash\":\"%s\"}\n",
             ts, json, g_prev_hash, new_hash);

    /* Write to COM port */
    BOOL ok = WriteFile(g_com_handle, entry, (DWORD)strlen(entry), &written, NULL);
    if (ok) {
        strncpy(g_prev_hash, new_hash, 64);
        g_prev_hash[64] = '\0';
        g_entry_count++;
        return 1;
    }
    return 0;
}

/* ── Service main loop ──────────────────────────────────────────────── */
static void service_main_loop(void) {
    char hostname[256] = {0};
    DWORD hostname_len = sizeof(hostname);
    GetComputerName(hostname, &hostname_len);

    /* Initialize prev_hash to genesis */
    memset(g_prev_hash, '0', 64);
    g_prev_hash[64] = '\0';

    /* Open COM port */
    g_com_handle = CreateFile(g_com_port, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_com_handle == INVALID_HANDLE_VALUE) return;

    /* Configure serial port */
    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(g_com_handle, &dcb);
    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    SetCommState(g_com_handle, &dcb);

    /* Write startup entry */
    char start_msg[256];
    snprintf(start_msg, sizeof(start_msg),
             "CareFortress Windows agent started on %s via %s", hostname, g_com_port);
    write_entry("START", start_msg);

    /* Heartbeat loop */
    while (WaitForSingleObject(g_stop_event, HEARTBEAT_INTERVAL * 1000) == WAIT_TIMEOUT) {
        char hb_msg[256];
        snprintf(hb_msg, sizeof(hb_msg), "periodic check from %s", hostname);
        write_entry("HEARTBEAT", hb_msg);
    }

    write_entry("STOP", "CareFortress Windows agent stopping");
    CloseHandle(g_com_handle);
    g_com_handle = INVALID_HANDLE_VALUE;
}

/* ── Win32 Service control ──────────────────────────────────────────── */
static void report_svc_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    static DWORD check_point = 1;
    g_svc_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState            = state;
    g_svc_status.dwWin32ExitCode           = exit_code;
    g_svc_status.dwWaitHint                = wait_hint;
    g_svc_status.dwControlsAccepted        = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_svc_status.dwCheckPoint              = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : check_point++;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);
}

static VOID WINAPI svc_ctrl_handler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        report_svc_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_stop_event);
    }
}

static VOID WINAPI svc_main(DWORD argc, LPTSTR *argv) {
    g_svc_status_handle = RegisterServiceCtrlHandler(SERVICE_NAME, svc_ctrl_handler);
    if (!g_svc_status_handle) return;

    report_svc_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) { report_svc_status(SERVICE_STOPPED, NO_ERROR, 0); return; }

    if (!find_virtio_serial_port(g_com_port, sizeof(g_com_port))) {
        report_svc_status(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0);
        return;
    }

    report_svc_status(SERVICE_RUNNING, NO_ERROR, 0);
    service_main_loop();
    report_svc_status(SERVICE_STOPPED, NO_ERROR, 0);
}

/* ── Install / Uninstall ────────────────────────────────────────────── */
static void install_service(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { printf("OpenSCManager failed: %lu\n", GetLastError()); return; }

    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);

    SC_HANDLE svc = CreateService(scm, SERVICE_NAME, SERVICE_DISPLAY,
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   path, NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        SERVICE_DESCRIPTION desc = { SERVICE_DESC };
        ChangeServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
        printf("Service installed successfully.\n");
        CloseServiceHandle(svc);
    } else {
        printf("CreateService failed: %lu\n", GetLastError());
    }
    CloseServiceHandle(scm);
}

static void uninstall_service(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { printf("OpenSCManager failed: %lu\n", GetLastError()); return; }
    SC_HANDLE svc = OpenService(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        printf("Service uninstalled.\n");
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

/* ── Entry point ────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "install") == 0)   { install_service();   return 0; }
        if (strcmp(argv[1], "uninstall") == 0) { uninstall_service(); return 0; }
    }

    SERVICE_TABLE_ENTRY dispatch[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)svc_main },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcher(dispatch);
    return 0;
}
