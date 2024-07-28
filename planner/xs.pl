use strict;
use warnings;

use File::Temp 'tempfile';

my (@compiler_flags, @linker_flags);

if ($^O ne 'MSWin32') {
	unshift @compiler_flags, '-pthread';
	unshift @linker_flags  , '-pthread';
}

load_module('Dist::Build::XS');
load_module('Dist::Build::XS::Conf');

my @sources = map { "src/$_.c" } qw{argon2 core encoding thread blake2/blake2b switch};

sub add_source {
	my ($name, $input_base, @flags) = @_;
	push @sources, {
		source  => "src/$input_base.c",
		object  => "src/$name.o",
		flags   => \@flags,
		defines => { fill_segment => "fill_segment_$name" },
	};
}

sub try_optimized {
	my ($name, $flag, $code) = @_;
	my $can_build = try_compile_run(source => $code, define => "HAVE_\U$name", extra_compiler_flags => [ $flag ], run => 0);
	add_source($name, 'opt', $flag) if $can_build;
}

add_source('ref', 'ref');

try_optimized('sse3', '-msse3', <<'EOF');
#include <immintrin.h>
int main () {
    __m128i input, output;
	output = _mm_loadu_si128(&input);
}
EOF

try_optimized('avx2', '-march=haswell', <<'EOF');
#include <immintrin.h>
int main () {
    __m256i input, output;
	output = _mm256_loadu_si256(&input);
}
EOF

try_optimized('avx512', '-march=skylake-avx512', <<'EOF');
#include <immintrin.h>
int main () {
    __m512i input, output;
	output = _mm512_loadu_si512(&input);
}
EOF

add_xs(
	extra_sources        => \@sources,
	extra_compiler_flags => \@compiler_flags,
	extra_linker_flags   => \@linker_flags,
);
