use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
our $HttpConfig = qq{
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
    lua_package_path "$pwd/lib/?.lua;$pwd/src/?.lua;;";
    lua_package_cpath "$pwd/?.so;;";
};

no_long_string();
run_tests();

__DATA__

=== TEST 1: randomized authenticated tokens and legacy rejection
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local encrypt = ndk.set_var.set_encrypt_session
            local decrypt = ndk.set_var.set_decrypt_session
            local a, b = encrypt("same value"), encrypt("same value")
            assert(a ~= b and #a >= 65)
            assert(decrypt(a) == "same value")
            for _, i in ipairs({1, 2, 18, #a}) do
                local byte = string.byte(a, i)
                local altered = a:sub(1, i-1) .. string.char((byte+1)%256) .. a:sub(i+1)
                assert(decrypt(altered) == "")
            end
            assert(decrypt(string.rep("x",32)) == "")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
