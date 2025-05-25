#include <dlfcn.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <sstream>
#include <thread>
#include "log.h"
#include "xdl.h"
#include "frida-gum.h"
#include "il2cpp_trace.h"




#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API


char data_dir_path[PATH_MAX];
static uint64_t il2cpp_base = 0;


typedef struct _TraceListener TraceListener;
struct _TraceListener
{
    GObject parent;

    guint num_calls;
};

static void trace_listener_iface_init (gpointer g_iface, gpointer iface_data);

#define Trace_TYPE_LISTENER (trace_listener_get_type ())
G_DECLARE_FINAL_TYPE (TraceListener, trace_listener, Trace, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED (TraceListener,
                        trace_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                                               trace_listener_iface_init))


GumInterceptor * interceptor;
GumInvocationListener * listener;


static void
trace_listener_on_enter (GumInvocationListener * listener,
                           GumInvocationContext * ic)
{
    long fun_offset = GUM_IC_GET_FUNC_DATA (ic, long);
    LOGD("0x%llx calling",fun_offset);
}

static void
trace_listener_on_leave (GumInvocationListener * listener,
                           GumInvocationContext * ic)
{
}

static void
trace_listener_class_init (TraceListenerClass * klass)
{
    (void) Trace_IS_LISTENER;
    (void) glib_autoptr_cleanup_TraceListener;
}

static void
trace_listener_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
    GumInvocationListenerInterface * iface = (GumInvocationListenerInterface*)g_iface;

    iface->on_enter = trace_listener_on_enter;
    iface->on_leave = trace_listener_on_leave;
}

static void
trace_listener_init (TraceListener * self)
{
}

void frida_gum_init(){
    gum_init_embedded();
    interceptor = gum_interceptor_obtain();
    listener = (GumInvocationListener *)g_object_new (Trace_TYPE_LISTENER, NULL);
}



void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}


int init_il2cpp_fun(){
    char* il2cpp_module_name = "libil2cpp.so";
    void *handle = xdl_open(il2cpp_module_name, 0);
    if (handle) {
        int flag = -1;
        init_il2cpp_api(handle);
        if(il2cpp_capture_memory_snapshot && il2cpp_free_captured_memory_snapshot && il2cpp_class_get_methods){
            flag = 0;
            Dl_info dlInfo;
            if (dladdr((void *) il2cpp_capture_memory_snapshot, &dlInfo)) {
                il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
                LOGD("il2cpp_base: %llx", il2cpp_base);
            }
        }
        return flag;
    } else{
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
    return -1;
}

char* get_data_dir_path(){
    char data_dir_path[PATH_MAX];
    std::ifstream file("/proc/self/cmdline");
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf(); // 读取文件内容到 stringstream
    snprintf(data_dir_path, PATH_MAX, "/data/data/%s",buffer.str().c_str());
    file.close();
    return data_dir_path;
}

char *get_trace_info(char *trace_file_path){
    FILE* file = fopen(trace_file_path, "r");
    if (!file) {
        LOGE("can not open:%s",trace_file_path);
        return NULL;
    }

    char buffer[1024];
    char last_line[1024];
    while (fgets(buffer, sizeof(buffer), file)){
        strcpy(last_line,buffer);
    }

    fclose(file);
    return last_line;
}




void check_all_methods(void *klass) {
    gum_interceptor_begin_transaction (interceptor);
    void *iter = nullptr;
    long fun_offset;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            fun_offset = (uint64_t)method->methodPointer - il2cpp_base;
            gum_interceptor_attach (interceptor,
                                    GSIZE_TO_POINTER (method->methodPointer),
                                    listener,
                                    GSIZE_TO_POINTER (fun_offset));
//            LOGD("success hook fun:0x%lx",fun_offset);
        }
    }
    LOGD("success hook all fun");
    gum_interceptor_end_transaction(interceptor);
}

void trace_type_info(Il2CppMetadataType type_info) {
    auto klass = reinterpret_cast<void *>(type_info.typeInfoAddress);
    check_all_methods(klass);
}



void start_trace(char* data_dir_path){
    char trace_file_path[PATH_MAX];

    int init_ret = init_il2cpp_fun();
    if(init_ret == -1){
        LOGE("can not get some fun addr");
        return;
    }
    LOGD("success get il2cpp api fun");

    frida_gum_init();
    LOGD("frida gum init success");

    strcpy(trace_file_path,data_dir_path);
    strcat(trace_file_path,"/files/test_trace.txt");
    LOGD("get trace_file_path:%s",trace_file_path);

    char* tinfo = get_trace_info(trace_file_path);
    if (tinfo == NULL || tinfo[0] == '\0') {
        LOGE("can not get any trace item");
        return;
    }
    LOGD("get trace item:%s",tinfo);

//    char test_assemblyName[100];
    char test_clazzName[240];
    strcpy(test_clazzName,tinfo);
    test_clazzName[strlen(test_clazzName)-1] = '\0';

//    char* split_str = strstr(tinfo,"+");
//    if(split_str==NULL){
//        LOGE("can not find split char +");
//        return;
//    }
//
//    strncpy(test_assemblyName,tinfo,split_str-tinfo);
//    strcpy(test_clazzName,split_str+1);
//    test_clazzName[strlen(test_clazzName)-1] = '\0';
//    LOGD("assemblyName:%s,clazzName:%s",test_assemblyName,test_clazzName);

    if (il2cpp_base!=0) {
        auto memorySnapshot = il2cpp_capture_memory_snapshot();
        auto all_type_infos_count = memorySnapshot->metadata.typeCount;
        auto all_type_infos = memorySnapshot->metadata.types;
        LOGD("all_typeCount:%d",all_type_infos_count);
        for (int i = 0; i < all_type_infos_count; ++i) {
            if(strcmp(all_type_infos[i].name,test_clazzName)==0){
                LOGD("trace start");
                trace_type_info(all_type_infos[i]);
                break;
            }
        }
        il2cpp_free_captured_memory_snapshot(memorySnapshot);
    } else {
        LOGE("unknow error");
    }


}



void trace_entry(){
    strcpy(data_dir_path,get_data_dir_path());
    if (data_dir_path == NULL || data_dir_path[0] == '\0') {
        LOGE("Failed to open cmdline");
        return;
    }

    LOGI("game dir:%s", data_dir_path);
    std::thread il2cpp_trace_thread(start_trace, data_dir_path);
    il2cpp_trace_thread.detach();

}
__attribute__((section(".init_array"))) void (*start_fun)() = trace_entry;