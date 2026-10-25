# vi:filetype=perl

use Test::Nginx::Socket::Lua;

repeat_each(1);
plan tests => repeat_each() * blocks() * 3;
no_long_string();
run_tests();

__DATA__

=== TEST 1: independent token vector and expiration
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            -- Generated independently using openssl enc and Python hmac.
            local valid = ngx.decode_base64("AQABAgMEBQYHCAkKCwwNDg8wHLhcqphxAGw+4b6eKNQ0XXjKwqCrjv/RT/DC2aaEzt+1JFWadoSoLuW/cnlBl3SZmNKN5UjPPYmLm1l+lcnc")
            local expired = ngx.decode_base64("AQABAgMEBQYHCAkKCwwNDg+au6AHza8Q2hKgHeOkfQN49/7CeBbZ+J1/2GFqPw/Us/neLhV086Y7OiiufhXhVnlGRHqb7+WkCeZ8Xu76z2zA")
            local decrypt = ndk.set_var.set_decrypt_session
            ngx.say(decrypt(valid) == "known vector\0value")
            ngx.say(decrypt(expired) == "")
            ngx.say(decrypt(valid) == "known vector\0value")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
--- no_error_log
[error]



=== TEST 2: IV and first ciphertext block vary for identical plaintext prefixes
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_iv "fixed iv";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            local encrypt = ndk.set_var.set_encrypt_session
            local decrypt = ndk.set_var.set_decrypt_session
            local prefix = "0123456789abcdef"
            local a = encrypt(prefix .. "one")
            local b = encrypt(prefix .. "two")
            local c = encrypt(prefix .. "one")
            ngx.say(#a == 81 and #b == 81 and #c == 81)
            ngx.say(a:byte(1) == 1 and b:byte(1) == 1)
            ngx.say(a:sub(2, 17) ~= b:sub(2, 17))
            ngx.say(a:sub(18, 33) ~= b:sub(18, 33))
            ngx.say(a:sub(2, 17) ~= c:sub(2, 17))
            ngx.say(a:sub(18, 33) ~= c:sub(18, 33))
            ngx.say(decrypt(a) == prefix .. "one")
            ngx.say(decrypt(b) == prefix .. "two")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
true
true
true
true
true
--- no_error_log
[error]



=== TEST 3: every token byte is authenticated and malformed tokens are rejected
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            local encrypt = ndk.set_var.set_encrypt_session
            local decrypt = ndk.set_var.set_decrypt_session
            local token = encrypt("authenticated value")
            local rejected = 0
            for i = 1, #token do
                local altered = token:sub(1, i - 1)
                                .. string.char((token:byte(i) + 1) % 256)
                                .. token:sub(i + 1)
                if decrypt(altered) == "" then
                    rejected = rejected + 1
                end
            end

            ngx.say(rejected == #token)
            rejected = 0
            for i = 0, #token - 1 do
                if decrypt(token:sub(1, i)) == "" then
                    rejected = rejected + 1
                end
            end

            ngx.say(rejected == #token)
            ngx.say(decrypt(token .. "x") == "")
            ngx.say(decrypt(token) == "authenticated value")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
true
--- no_error_log
[error]



=== TEST 4: legacy token from the old sanity test is rejected
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            local old = ndk.set_var.set_decode_base32(
                "ktrp3n437q42laejppc9d4bg0jpv0ejie106ooo65od9lf5huhs0====")
            ngx.say(#old == 32)
            ngx.say(ndk.set_var.set_decrypt_session(old) == "")
            local token = ndk.set_var.set_encrypt_session("abc")
            ngx.say(ndk.set_var.set_decrypt_session(token) == "abc")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
--- no_error_log
[error]



=== TEST 5: binary values and block boundaries round trip
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            local encrypt = ndk.set_var.set_encrypt_session
            local decrypt = ndk.set_var.set_decrypt_session
            local passed = 0
            for _, len in ipairs({0, 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 32, 1024}) do
                local value = string.rep("\0", len)
                local token = encrypt(value)
                local expected = 49 + (math.floor((len + 8) / 16) + 1) * 16
                if #token == expected and decrypt(token) == value then
                    passed = passed + 1
                end
            end

            ngx.say(passed)
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
13
--- no_error_log
[error]



=== TEST 6: authentication rejects a different key while configured IV is ignored
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /other-key {
        encrypted_session_key "123456abcdefghijklmnopqrstuvwxyz";
        content_by_lua_block {
            local token = ngx.decode_base64(ngx.req.get_uri_args().token)
            ngx.print(ndk.set_var.set_decrypt_session(token))
        }
    }

    location = /other-iv {
        encrypted_session_iv "another iv";
        content_by_lua_block {
            local token = ngx.decode_base64(ngx.req.get_uri_args().token)
            ngx.print(ndk.set_var.set_decrypt_session(token))
        }
    }

    location = /t {
        content_by_lua_block {
            local token = ndk.set_var.set_encrypt_session("same key")
            local options = { args = { token = ngx.encode_base64(token) } }
            local other_key = ngx.location.capture("/other-key", options)
            local other_iv = ngx.location.capture("/other-iv", options)
            ngx.say(other_key.status, " ", other_key.body == "")
            ngx.say(other_iv.status, " ", other_iv.body)
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
200 true
200 same key
--- no_error_log
[error]



=== TEST 7: authenticated malformed plaintext is rejected and cipher context recovers
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            -- Independent vectors with valid HMACs and invalid CBC payloads.
            local bad_padding = ngx.decode_base64("AQABAgMEBQYHCAkKCwwNDg8AAAAAAAAAAAAAAAAAAAAA8cnoax+tYKZChe19vAwgTkzfV8ZZsKucaux6G8LyA40=")
            local no_expiry = ngx.decode_base64("AQABAgMEBQYHCAkKCwwNDg8/3ncdB5RAYVYEWd2Dl6uJdvZc/qQ3W4n9PbjqcBRucgdLVC5fVZ1SP0aiT/3VtxQ=")
            local decrypt = ndk.set_var.set_decrypt_session
            ngx.say(decrypt(bad_padding) == "")
            ngx.say(decrypt(no_expiry) == "")
            local token = ndk.set_var.set_encrypt_session("after invalid padding")
            ngx.say(decrypt(token) == "after invalid padding")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
--- no_error_log
[error]



=== TEST 8: configured keys stay isolated and inherited keys survive alternating use
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /key-a {
        content_by_lua_block {
            local token = ngx.req.get_uri_args().token
            if token then
                ngx.print(ndk.set_var.set_decrypt_session(ngx.decode_base64(token)))

            else
                ngx.print(ngx.encode_base64(ndk.set_var.set_encrypt_session("cached key value")))
            end
        }
    }

    location /key-b/ {
        encrypted_session_key "123456abcdefghijklmnopqrstuvwxyz";
        content_by_lua_block {
            local token = ngx.req.get_uri_args().token
            if token then
                ngx.print(ndk.set_var.set_decrypt_session(ngx.decode_base64(token)))

            else
                ngx.print(ngx.encode_base64(ndk.set_var.set_encrypt_session("cached key value")))
            end
        }

        location = /key-b/inherited {
            content_by_lua_block {
                local token = ngx.req.get_uri_args().token
                if token then
                    ngx.print(ndk.set_var.set_decrypt_session(ngx.decode_base64(token)))

                else
                    ngx.print(ngx.encode_base64(ndk.set_var.set_encrypt_session("cached key value")))
                end
            }
        }
    }

    location = /t {
        content_by_lua_block {
            local paths = { "/key-a", "/key-b/", "/key-b/inherited" }
            local passed = 0
            for round = 1, 3 do
                for i, source in ipairs(paths) do
                    local issued = ngx.location.capture(source)
                    assert(issued.status == 200 and #issued.body > 0)
                    for j, target in ipairs(paths) do
                        local res = ngx.location.capture(target, {
                            args = { token = issued.body }
                        })
                        local expected = (i == 1) == (j == 1)
                                         and "cached key value" or ""
                        if res.status == 200 and res.body == expected then
                            passed = passed + 1
                        end
                    end
                end
            end

            ngx.say(passed)
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
27
--- no_error_log
[error]
