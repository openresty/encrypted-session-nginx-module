# vi:filetype=perl

use File::Temp qw(tempdir);
use Test::More ();

BEGIN {
    Test::More::plan(skip_all =>
                    'RAND_bytes fault injection requires Linux LD_PRELOAD')
        if $^O ne 'linux';

    my $dir = tempdir('encrypted-session-random-XXXXXX', TMPDIR => 1,
                      CLEANUP => 1);
    my $lib = "$dir/random-failure.so";
    system($ENV{CC} || 'cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
           't/random-failure.c', '-o', $lib, '-ldl') == 0
        or Test::More::BAIL_OUT('cannot build RAND_bytes fault injector');

    # Let Test::Nginx inherit LD_PRELOAD before it initializes its environment.
    # Per-test preload assignments otherwise become the Valgrind executable.
    $ENV{LD_PRELOAD} = join ' ', $lib, ($ENV{LD_PRELOAD} || ());
}

use Test::Nginx::Socket::Lua;

workers(1);
repeat_each(1);
plan tests => repeat_each() * blocks() * 4;
no_long_string();
run_tests();

__DATA__

=== TEST 1: failed random IV generation emits no token and later requests recover
--- http_config
    encrypted_session_key "abcdefghijklmnopqrstuvwxyz123456";
    encrypted_session_expires 0;
--- config
    location = /t {
        content_by_lua_block {
            local ffi = require "ffi"
            ffi.cdef[[void encrypted_session_test_rand_fail(int enabled);]]
            local encrypt = ndk.set_var.set_encrypt_session
            local decrypt = ndk.set_var.set_decrypt_session
            local before = encrypt("before failure")
            ffi.C.encrypted_session_test_rand_fail(1)
            ngx.say(encrypt("must not emit a token") == "")
            ffi.C.encrypted_session_test_rand_fail(0)
            local after = encrypt("after failure")
            ngx.say(decrypt(after) == "after failure")
            ngx.say(decrypt(before) == "before failure")
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body
true
true
true
--- error_log
encrypted_session: failed to generate session IV
--- no_error_log
[alert]
