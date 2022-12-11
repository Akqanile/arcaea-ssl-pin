#include <dobby.h> // DobbyHook, dobby_dummy_func_t
#include <dlfcn.h> // dlsym, dlopen, RTLD_LAZY
#include <unistd.h> // strstr, getpid
#include <stdlib.h> // strtoul
#include <android/log.h> // __android_log_print

#define CREATE_HOOK_FUNCTION(name, parameters, return_type)\
return_type (*orig_##name) parameters; \
return_type hook_##name parameters

unsigned long BASE = 0;
const char* TARGET_LIBRARY = "libcocos2dcpp.so";

// yoinked from https://github.com/BlackTeaML/Android-ML/blob/a5bc6f9cdf9c14e03b20e9f0dea6adc7658d9263/x32/jni/include/Utils.h
unsigned long get_base_address(const char* library_name) {
    /*
        MIT License

        Copyright (c) 2021 BlackTea ML

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.
    */

    unsigned long addr = 0;
    char filename[32], buffer[1024];

    snprintf(filename, sizeof(filename), "/proc/%d/maps", getpid());

    FILE *fp = fopen(filename, "rt");
    
    if (fp != nullptr)
    {
        while (fgets(buffer, sizeof(buffer), fp))
        {
            if (strstr(buffer, library_name))
            {
                addr = strtoul(buffer, NULL, 16);
                break;
            }
        }
    }

    fclose(fp);

    return addr;
}

CREATE_HOOK_FUNCTION(X509_verify_cert, (void* ctx), int)
{
    __android_log_print(ANDROID_LOG_DEBUG, "ayaya", "X509_verify_cert");
    orig_X509_verify_cert(ctx);

    return 1;
}

CREATE_HOOK_FUNCTION(sub_4A6494, (void* ptr, int i), int)
{
    __android_log_print(ANDROID_LOG_DEBUG, "ayaya", "sub_4A7494");
    orig_sub_4A6494(ptr, i);

    return 0;
}

__attribute__((__constructor__)) void hannei()
{
    BASE = get_base_address(TARGET_LIBRARY);

    DobbyHook(
        // I used lief to add the library as a dependency for cocos2dcpp
        // But that adds 4096 bytes and messed the offset a bit.
        // Alternatively, you can load the library manually using smali.
        (void*)(BASE + 0x4A6494 + 0x1000),
        (dobby_dummy_func_t)hook_sub_4A6494,
        (dobby_dummy_func_t*)&orig_sub_4A6494
    );

    DobbyHook(
        (void*)dlsym(dlopen(TARGET_LIBRARY, RTLD_LAZY), "X509_verify_cert"),
        (dobby_dummy_func_t)hook_X509_verify_cert,
        (dobby_dummy_func_t *)&orig_X509_verify_cert
    );
}
