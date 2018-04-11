use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
  module_name  => 'Crypt::Argon2',
  c_source     => 'src',
  include_dirs => 'include',
##{ $plugin->get_prereqs ##}
);

if ($^O ne 'MSWin32') {
	$builder->extra_linker_flags('-lpthread');
}

$builder->create_build_script();
