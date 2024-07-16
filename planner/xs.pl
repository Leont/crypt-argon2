use strict;
use warnings;

use File::Temp 'tempfile';

my (@compiler_flags, @linker_flags);
my $impl = 'ref/ref.c';

if ($ENV{PERL5_CPAN_IS_RUNNING}) {
	my $checker = ExtUtils::Builder::Planner->new;
	$checker->load_module('ExtUtils::Builder::AutoDetect::C');

	my $arch = $ENV{CRYPT_ARGON2_ARCH} || 'native';
	my @flags = $arch eq 'NONE' ? () : ( "-march=$arch" );

	my (undef, $target) = tempfile('compile_checkXXXX', TMPDIR => 1, UNLINK => 1, SUFFIX => '.o', OPEN => 0);

	$checker->compile('opt/opt.c', $target, include_dirs => [ 'include', 'src' ], extra_args => \@flags);
	if (eval { $checker->materialize->run($target); 1 }) {
		$impl = 'opt/opt.c';
		@compiler_flags = @flags;
	};
};

if ($^O ne 'MSWin32') {
	unshift @compiler_flags, '-pthread';
	unshift @linker_flags, '-pthread';
}

my @sources = map { "src/$_.c" } qw{argon2 core encoding thread blake2/blake2b};

load_module("Dist::Build::XS");
add_xs(
	extra_sources        => [ @sources, $impl ],
	extra_compiler_flags => \@compiler_flags,
	extra_linker_flags   => \@linker_flags,
	include_dirs         => [ 'src' ],
);
