from binaryninja import *
import os
import getpass

bitsize = 32 
max_len = 512

llvm_fuzzer_func = "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)"
afl_fuzzer_func  =  "int main(int argc, char *argv[])"

afl_fuzzer_loop = "while (__AFL_LOOP(1000))"
afl_fuzzer_loop_init = """
    char Buf[{max_len}];
    char* Data = NULL;
    int Size = {max_len};
""".format(max_len=max_len)

afl_fuzzer_loop_load = """
        /* Reset state. */
        memset(Buf, 0, {max_len});

        /* Read input data. */
        read(0, Buf, {max_len});
        Data = &Buf[0];
""".format(max_len=max_len)


llvm_fuzzer_loop = "while ( 1 )"

fuzzer_func = afl_fuzzer_func
fuzzer_loop = afl_fuzzer_loop
fuzzer_loop_init = afl_fuzzer_loop_init
fuzzer_loop_load = afl_fuzzer_loop_load

template = """
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h> 

int isLoaded = 0;
void *{libname} = NULL;

{typedefs}

{globaldefs}

void CloseLibrary()
{{
    if({libname}){{
	    dlclose({libname});
	    {libname} = NULL;
    }}
    return;
}}

int LoadLibrary()
{{
    {libname} = dlopen("{libname}.so", RTLD_NOW|RTLD_GLOBAL);

    fprintf(stderr, "%s\\n", dlerror());

    printf("loaded {libname} at %p\\n", {libname});
    atexit(CloseLibrary);
    return {libname} != NULL;
}}

void ResolveSymbols()
{{
    {dlsyms} 
}}

{fuzzer_func}
{{
    {fuzzer_loop_init}

    if (!isLoaded)
    {{
        if(!LoadLibrary()) 
        {{
            printf("could not load {libname}.so\\n");
            return -1;
        }}
        ResolveSymbols();
        isLoaded = 1;
    }}

    if (Size==0)
    {{
        return 0;
    }}

    uint8_t choice = 0;

    {fuzzer_loop}
    {{

        {fuzzer_loop_load}

        if ( Size < sizeof(choice) ) 
        {{
            break;
        }}

        choice = Data[0];
        Data += sizeof(choice);
        Size -= sizeof(choice);

        switch(choice % {number}) 
        {{
            {choices}
        }}

    }}

    return 0;
}}
"""

class Function():
    def __init__(self, function):
        self._name = function.name
        self._type = function.function_type
        self._argument_types = convert_function_parameter_types(function.function_type.parameters)

    def typedef(self):
        argument_types = convert_function_parameter_types(self._type.parameters)
        ret = binja_type_to_c_type(str(self._type.return_value))

        return "typedef %s(*%s_t)(%s);" % (ret, self._name, ",".join(argument_types))

    def resolve(self, libname):
	return self.dlsym(libname) +" " + self.printer()

    def dlsym(self, libname):
        return ("%s = (%s_t)dlsym({libname}, \"%s\");" % (self._name, self._name, self._name)).format(libname=libname)

    def printer(self):
        return "printf(\"loaded %s at %%p\\n\", %s);" % (self._name, self._name)

    def globaldef(self):
        return "%s_t %s = NULL;" % (self._name, self._name)

    def choice(self, number):
        localVars=[]
        args = []
        frees = []
        minbufsize=0
        idx = ["0"];
        lvaridx = number*1000
        # (int, int, int, int*)
        # (char *, int, int)
        
        for parameter in self._type.parameters:
            if not ("*" in str(parameter.type)):
                tmp_type = binja_type_to_c_type(str(parameter.type))
                tmp_type_size = get_c_type_byte_size(tmp_type)
                localVars.append("%s l_%s; memcpy(&l_%s, Data+(%s), sizeof(%s));" %(tmp_type, lvaridx, lvaridx, " + ".join(idx), tmp_type))
                args.append("l_%s" % lvaridx)
                lvaridx += 1

                minbufsize += tmp_type_size
                idx.append(str(tmp_type_size))
            else:
                localVars.append("""
                unsigned int strlen_%s; memcpy(&strlen_%s, Data+(%s), sizeof(int));
                if(strlen_%s > Size){
                        //not enough bytes in buffer
                        return 0;
                }
                char *tmpbuf_%s = malloc(strlen_%s+1);
                if(tmpbuf_%s == NULL){
                        //could not allocate tmpstring
                        return 0;
                }
                strncpy(tmpbuf_%s, Data+(%s)+4, strlen_%s);
                tmpbuf_%s[strlen_%s] = 0;
                """ % (lvaridx, lvaridx, " + ".join(idx), lvaridx, lvaridx, lvaridx, lvaridx, lvaridx, " + ".join(idx), lvaridx, lvaridx, lvaridx))
                args.append("tmpbuf_%s" % lvaridx)
                frees.append("free(tmpbuf_%s);" %(lvaridx));
                lvaridx += 1
                minbufsize += 5 
                idx.append("4")
                idx.append("strlen_%s" % (lvaridx))

        return """
           case {number}:
                if( Size < ({idx}) ){{
                    //printf("not enough buffer space.\\n");
                    return 0;
                }}
                {localVars}
                {function}({args});
                Data += Size;
                Size -= Size;
                {frees}
                break;
        """.format(idx=minbufsize, localVars=" ".join(localVars), number=number, function=self._name, args=", ".join(args), frees=" ".join(frees))

def get_c_type_byte_size(c_type):
    mapping = {"long long int":8, "int":4, "unsigned int":4, "void":4, "short":2, "char":1}
    
    if not (c_type in mapping):
        raise Exception("Unknown type '%s'" % c_type)
    
    return mapping[c_type]

def binja_type_to_c_type(binja_type):
    if len(binja_type.split()) > 1:
        return " ".join( map(binja_type_to_c_type, binja_type.split()))
    mapping = { "int64_t":"long long int", "int32_t":"int", "uint32_t":"unsigned int", "void":"void", "char":"char", "int16_t":"short int", "const":"const" }

    has_pointer = ""
    if "*" in binja_type:
        has_pointer = "*"
    tmp_type = binja_type.replace("*", "")
    if not (tmp_type in mapping):
        raise Exception("Unknown type '%s'" % binja_type)
    return "%s%s" % (mapping[tmp_type], has_pointer)

def convert_function_parameter_types(function_parameters):
    function_types = []
    for parameter in function_parameters:
        function_types.append( binja_type_to_c_type(str(parameter.type)))
    return function_types      

def get_type_for_function(function):
    filtered_funcs = [
            "_start", 
            "_init", 
            "_fini", 
            "__stack_chk_fail_local", 
            "__stack_chk_fail", 
            "strcmp", 
            "strcpy", 
            "__cxa_finalize",
            "deregister_tm_clones",
            "register_tm_clones",
            "__do_global_dtors_aux",
            "frame_dummy",
            "__x86.get_pc_thunk.ax",
            "__x86.get_pc_thunk.dx",
            "__gmon_start__",
    ]

    if function.name in filtered_funcs:
        return

    return Function(function)

def get_types(bv):
    types = []
    for function in bv.functions:
        tmp = get_type_for_function(function)
        
        if not tmp:
            continue
        
        types.append( tmp )

    return types

def write_template(libname, f_types):
    with open("c:\\Users\\%s\\Desktop\\harness.c" % getpass.getuser(), 'w+') as f:
        f.write(template.format(
                libname=libname,
                max_len=max_len,
                fuzzer_loop=fuzzer_loop,
                fuzzer_loop_init=fuzzer_loop_init,
                fuzzer_loop_load=fuzzer_loop_load,
                fuzzer_func=fuzzer_func,
                typedefs   ="\n".join(map(lambda a: a.typedef(), f_types)), 
                dlsyms     ="\n    ".join(map(lambda a: a.resolve(libname),   f_types)),
                globaldefs ="\n".join(map(lambda a: a.globaldef(), f_types)),
                choices    ="\n".join([a.choice(i) for i, a in enumerate(f_types)]),
                number = str(len(f_types))))


def create_for_function(bv, func):
    libname = os.path.basename(bv.file.filename).split(".")[0]
    f_types = [get_type_for_function(func)]
    print(f_types)
    if len(f_types) == 0:
        print("No usable functions found")
        return

    write_template(libname, f_types)
    
def create(bv):
    libname = os.path.basename(bv.file.filename).split(".")[0]
    f_types = get_types(bv)
    if len(f_types) == 0:
        print("No usable functions found")
        return

    write_template(libname, f_types)
   
PluginCommand.register("Create test harness", "Attempt to create a test harness for exported functions of this shared library", create)
PluginCommand.register_for_function("Create test harness for function", "Attempt to create a test harness for the selected function", create_for_function)
