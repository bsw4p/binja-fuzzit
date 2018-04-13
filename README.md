# binja-fuzzit
Generate a fuzzing harness for (shared) libraries from Binary Ninja


## Tutorial

1. Build the following shared library using 
```gcc -g -O0 -shared -fPIC vulns_shared.c -o vulns_shared.so```
```c
#include <string.h>

int is_initialized=0;
char global_buf[128];

void init_buffer(){
        is_initialized=1;
}

int buffer_overflow(char *input){
        if(is_initialized){
                strcpy(&global_buf[0], input);
        }
}

int keyword_buffer_overflow(char *keyword, char *input){
        char buf[128];

        if(strlen(keyword) > 2){
                if(keyword[0] == 'k' && keyword[1] == 'w'){
                        strcpy(&buf[0], input);
                }
        }
}

int integer_overflow(int size, char *input){
        char buf[128];
        if(size < 128){
                strcpy(&buf[0], input);
        }
}
```

2. Load shared library into binary ninja

3. Create harness using binja-fuzzit

4. Compile harness.c using ```gcc -ldl harness.c -o harness``` 

5. Run AFL with command ```AFL_INST_LIBS=1 AFL_NO_FORKSRV=1 ~/afl-2.52b/afl-fuzz -Q -iin -oout --  ./harness```
