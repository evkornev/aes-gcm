describe("lua aes_gcm", function()
    it("loads aes_gcm module", function()
        require 'aes_gcm'
    end)

    local aes_gcm = require'aes_gcm'

    it("can encypt/decrypt AES_128_GCM", function()
        local key = "\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb\xcc\xdd"
        local iv = "\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb\xcc\xdd\xee\xff";
        local aad = "\xaa\xbb\xcc";
        local plain_text = "\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb\xcc\xdd\xee\xff"
        assert.has_no_error(function()
            aes_gcm.encrypt(key, iv, aad, plain_text)
        end)
        local cipher_text, tag = aes_gcm.encrypt(key, iv, aad, plain_text)
        assert.has_no_error(function()
            aes_gcm.decrypt(key, iv, aad, cipher_text, tag)
        end)
        local _plain_text = aes_gcm.decrypt(key, iv, aad, cipher_text, tag)
        assert.is_equal(plain_text, _plain_text)
    end)
end)