use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::Find;

my %build_spec = (
  name => "lib/Crypt/Argon2",
  c_source => 'src',
  include_dirs => [ 'include' ],
);

sub make_inc {
  my ($spec) = @_;
  return (INC => join ' ', map { "-I$_" } @{ $spec->{include_dirs} });
}

sub find_c {
  my ($dir) = @_;
  my @files;
  File::Find::find(sub {
    return unless -f and /\.c$/;
    push @files, $File::Find::name;
  }, $dir);
  return @files;
}

sub make_obj {
  my ($spec) = @_;
  my $objects = join ' ', map { s#\.c$#\$(OBJ_EXT)#; $_ } find_c($spec->{c_source});
  return (XSBUILD => {
    xs => {
      $spec->{name} => {
        OBJECT => "$spec->{name}\$(OBJ_EXT) $objects",
      },
    },
  }),
}

WriteMakefile(
  NAME => 'Crypt::Argon2',
  VERSION_FROM => 'lib/Crypt/Argon2.pm',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 7.16,
  },
  XSMULTI => 1,
  make_obj(\%build_spec),
  make_inc(\%build_spec),
  META_MERGE => {
    "meta-spec" => { version => 2 },
    resources => {
      repository => {
        type => 'git',
        url => 'git@github.com:Leont/crypt-argon2.git',
        web => 'https://github.com/Leont/crypt-argon2',
      },
    },
  },
);
