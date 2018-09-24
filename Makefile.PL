use 5.010000;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Monitoring::Plugin::REST',
    VERSION_FROM      => 'lib/Monitoring/Plugin/REST.pm',
    PREREQ_PM         => {
        Carp                  => 0,
        LWP::UserAgent        => 0,
        HTTP::Status          => 0,
        YAML                  => 0,
        JSON                  => 0,
        Monitoring::Plugin    => 0,
        Class::Accessor       => 0,
    },
    TEST_REQUIRES     => {
        Test::More            => 0,
        HTTP::Response        => 0,
    },
    BUILD_REQUIRES    => {
        ExtUtils::MakeMaker   => 6.64,
        Pod::Readme           => 0,
    },
    ABSTRACT_FROM     => 'lib/Monitoring/Plugin/REST.pm',
    AUTHOR            => 'Rika Lena Denia <rika.denia@comnetgmbh.com>',
    LICENSE           => 'gpl_3',
);
