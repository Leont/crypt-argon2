use strict;
use warnings;
use Module::Build 0.3604;

use File::Spec;
use ExtUtils::CBuilder;
my $cbuilder = ExtUtils::CBuilder->new;
my %opt_args = (
	source               => 'opt/opt.c',
	object_file          => File::Spec->devnull,
	include_dirs         => [ 'include', 'src' ],
	extra_compiler_flags => [ '-march=native' ],
);

my $optimized = $ENV{PERL5_CPAN_IS_RUNNING} && eval { $cbuilder->compile(%opt_args) };
my ($dir, $compiler_flags, $linker_flags) = $optimized ? ('opt', ['-march=native']) : ('ref');

if ($^O ne 'MSWin32') {
	unshift @{ $compiler_flags }, '-pthread';
	unshift @{ $linker_flags }, '-pthread';
}

my $builder = Module::Build->new(
  module_name  => 'Crypt::Argon2',
  c_source     => [ 'src', $dir ],
  extra_compiler_flags => $compiler_flags,
  extra_linker_flags => $linker_flags,
  include_dirs => 'include',
##{ $plugin->get_prereqs ##}
  script_files => 'script/argon2-calibrate',
);

$builder->create_build_script();
