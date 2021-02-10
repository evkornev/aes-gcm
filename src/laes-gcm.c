/*
 * Lua lib wrapper
 */

#include <lua5.3/lauxlib.h>
#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>
#include "aes.h"

#define MAX_ENC_MSG_SIZE  1300
#define MAX_TAG_SIZE 16

static int encrypt(lua_State *L){
    size_t key_len = 0;
    size_t iv_len = 0;
    size_t aad_len = 0;
    size_t plaintext_len = 0;
    int result = 0;

    const unsigned char* key = luaL_checklstring(L, 1, &key_len);
    lua_assert(key_len == 16); // 128 bit key is a must
    const unsigned char* iv = luaL_checklstring(L, 2, &iv_len);
    const unsigned char* aad = luaL_checklstring(L, 3, &aad_len);
    const unsigned char* plaintext = luaL_checklstring(L, 4, &plaintext_len);

    unsigned char ciphertext[MAX_ENC_MSG_SIZE] = {0,};
    unsigned char tag[MAX_TAG_SIZE] = {0,};

    result = aes_gcm_ae(key, key_len,
                        iv, iv_len,
                        plaintext, plaintext_len,
                        aad, aad_len,
                        ciphertext, tag);
    if (!result)
    {
        lua_pushlstring(L, ciphertext, plaintext_len);
        lua_pushlstring(L, tag, MAX_TAG_SIZE);
        return 2;
    }
    else{
        luaL_error(L, "decrypt failed");
        return 0;
    }
}

static int decrypt(lua_State *L){
    size_t key_len = 0;
    size_t iv_len = 0;
    size_t aad_len = 0;
    size_t ciphertext_len = 0;
    size_t tag_len = 0;
    int result = 0;

    const unsigned char* key = luaL_checklstring(L, 1, &key_len);
    lua_assert(key_len == 16); // 128 bit key is a must
    const unsigned char* iv = luaL_checklstring(L, 2, &iv_len);
    const unsigned char* aad = luaL_checklstring(L, 3, &aad_len);
    const unsigned char* ciphertext = luaL_checklstring(L, 4, &ciphertext_len);
    const unsigned char* tag = luaL_checklstring(L, 5, &tag_len);
    unsigned char plaintext[MAX_ENC_MSG_SIZE] = {0,};
    result = aes_gcm_ad(key, key_len,
                        iv, iv_len,
                        ciphertext, ciphertext_len,
                        aad, aad_len,
                        tag, plaintext);
    if (!result)
    {
        lua_pushlstring(L, plaintext, ciphertext_len);
        return 1;
    }
    else{
        luaL_error(L, "decrypt failed %d", result);
        return 0;
    }

}

static const luaL_Reg aes_gcm[] = {
    {"encrypt", encrypt},
    {"decrypt", decrypt},
    {NULL, NULL},
};
int luaopen_aes_gcm(lua_State *L)
{
    luaL_newlib(L, aes_gcm);
    return 1;
}
