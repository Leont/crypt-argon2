use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
  module_name  => 'Crypt::Argon2',
  c_source     => 'src',
  include_dirs => 'include',
##{ $plugin->get_prereqs ##}
);

$builder->create_build_script();
