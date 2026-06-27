# Validating the `ruby-ext` ASan recipe

One-time check that the sanitized interpreter actually catches a memory bug in a native gem.
Needs Docker + network. The image build compiles Ruby (and Rust) from source — ~15–20 min.

## 1. Build the images

```bash
# from repo root
docker build -t scrutineer-runner:local -f Dockerfile.runner .
docker build -t scrutineer-profile-ruby-ext \
  -f docker/profiles/ruby-ext/Dockerfile \
  --build-arg RUNNER_IMAGE=scrutineer-runner:local \
  docker/profiles/ruby-ext
```

The image build itself is a partial gate: it fails if the configure flags are wrong (the
`ldd … | grep libasan` smoke step at the end of the Dockerfile won't pass).

## 2. Smoke test

```bash
docker run --rm scrutineer-profile-ruby-ext sh -c '
  ruby -v &&
  ldd /usr/local/ruby-asan/bin/ruby | grep libasan &&
  /usr/bin/ruby -v && valgrind --version && cargo --version && ruby-build --version'
```

## 3. Seed a buggy gem

A C extension that overflows a 16-byte heap buffer, reachable from Ruby:

```bash
mkdir -p /tmp/boom/ext/boom
cat > /tmp/boom/ext/boom/extconf.rb <<'RB'
require "mkmf"
create_makefile("boom")
RB
cat > /tmp/boom/ext/boom/boom.c <<'C'
#include <ruby.h>
#include <string.h>
/* vulnerable: copies the whole input into a fixed 16-byte heap buffer */
static VALUE boom_copy(VALUE self, VALUE str) {
  long n = RSTRING_LEN(str);
  char *buf = xmalloc(16);
  memcpy(buf, RSTRING_PTR(str), n);   /* heap-buffer-overflow when n > 16 */
  VALUE out = rb_str_new(buf, n);
  xfree(buf);
  return out;
}
void Init_boom(void) {
  VALUE m = rb_define_module("Boom");
  rb_define_module_function(m, "copy", boom_copy, 1);
}
C
cat > /tmp/boom/poc.rb <<'RB'
require_relative "ext/boom/boom"
Boom.copy("A" * 64)   # overflows the 16-byte buffer
puts "NO CRASH"
RB
```

## 4. Build under ASan + trigger

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd ext/boom && ruby extconf.rb && make && cd /src && ruby poc.rb'
```

**Pass:** aborts with `ERROR: AddressSanitizer: heap-buffer-overflow` and a `SUMMARY:` line in
`boom_copy` — **not** `NO CRASH`.

Negative control (must print `NO CRASH`, no ASan output):

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd /src && ruby -e "require_relative %q(ext/boom/boom); Boom.copy(%q(short)); puts %q(NO CRASH)"'
```

## 5. (optional) valgrind fallback + suppressions

Stock interpreter, separate uninstrumented build:

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd ext/boom && rm -f *.o *.so Makefile && /usr/bin/ruby extconf.rb && make && cd /src &&
  valgrind --suppressions=/usr/local/share/ruby-ext/ruby.supp --error-exitcode=99 /usr/bin/ruby poc.rb'
```

**Pass:** `Invalid write of size …` in `boom_copy`, exit 99, with no GC-noise errors leaking past
the suppressions.

## If ASan doesn't fire / the interpreter crashes in the GC

Tune in `docker/profiles/ruby-ext/Dockerfile` (open question #1), rebuild, retry:
- fiber-related crash in `gc.c`/`cont.c` → add `--with-coroutine=copy` to `./configure`.
- noisy/false GC reports → confirm `ASAN_OPTIONS` has `detect_stack_use_after_return=0`.
- shutdown leaks → `RUBY_FREE_AT_EXIT=1` is set; keep `detect_leaks=0` unless chasing one.
```
