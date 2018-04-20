# binja-fuzzit
Generate a fuzzing harness for (shared) libraries from Binary Ninja


## Tutorial

1. Build the following shared library using 
```gcc -g -O0 -shared -fPIC vulns_shared.c -o vulns_shared.so```
```c
#include <string.h>

int is_initialized=0;

void init_buffer(){
        printf("init buffer\n");
        is_initialized=1;
}

int buffer_overflow(char *input){
        char buf[128];
        printf("buffer_overflow\n");
        if(is_initialized){
                strcpy(&buf[0], input);
        }
}

int keyword_buffer_overflow(char *keyword, char *input){
        printf("keyword_buffer_overflow\n");
        char buf[128];

        if(strlen(keyword) >= 2){
                if(keyword[0] == 'k' && keyword[1] == 'w'){
                        strcpy(&buf[0], input);
                }
        }
}

int integer_overflow(int size, char *input){
        printf("integer_overflow\n");
        char buf[128];
        if(size < 128){
                strcpy(&buf[0], input);
        }
}
```

2. Load shared library into binary ninja

3. Create harness using binja-fuzzit

4. Compile harness.c using ```gcc -ldl harness.c -o harness``` 

5. Test harness manually

Trigger buffer overflow:
```python
payload = [
        # trigger init()
        "\x00",
        # trigger buffer overflow
        "\x01",
        # string size
        "\xff\x00\x00\x00",
        # string
        "A"*0xff
]

print("".join(payload))
```

```bash
python trigger_bufferoverflow.py | LD_LIBRARY_PATH=. ./harness
```

Trigger keyword buffer overflow:
```python
payload = [
        # trigger keyword buffer overflow
        "\x02",
        # keyword string size
        "\x02\x00\x00\x00",
        # keyword string
        "kw",
        # string size
        "\xff\x00\x00\x00",
        "A"*0xff
]


print("".join(payload))
```

```bash
python trigger_keywordbufferoverflow.py | LD_LIBRARY_PATH=. ./harness
```


Trigger size buffer overflow:
```python
payload = [
        # trigger integer_overflow()
        "\x03",
        # integer size
        "\x01\x00\x00\x00",
        # string size
        "\xff\x00\x00\x00",
        # string
        "A"*0xff

]

print("".join(payload))
```

```bash
python trigger_sizebufferoverflow.py | LD_LIBRARY_PATH=. ./harness
```

6. Setup AFL
```bash
mkdir in
python -c 'print("\x00"*512)' > in/0
```

7. Run AFL with command ```LD_LIBRARY_PATH=. AFL_INST_LIBS=1 AFL_NO_FORKSRV=1 ~/afl-2.52b/afl-fuzz -Q -iin -oout --  ./harness```
