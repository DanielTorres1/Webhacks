use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'webHacks',
    AUTHOR           => q{Daniel Torres <daniel.torres@owasp.org>},
    VERSION_FROM     => 'lib/webHacks.pm',
    ABSTRACT_FROM    => 'lib/webHacks.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'Moose' => 0,
        'Net::SSL' => 0,
        'LWP::UserAgent' => 0,
        'Text::Table' => 0,
        'URI::Escape' => 0,
        'HTTP::Cookies' => 0,
        'HTTP::Request' => 0,
        'HTML::Scrubber' => 0,        
        'HTTP::Response' => 0,
        'Text::Unidecode' => 0,        
        'Getopt::Std' => 0,
        'Parallel::ForkManager' => 0,        
        'Term::ANSIColor' => 0,   
        'Math::Round' => 0,   
        'Switch' => 0,   
        
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'webHacks-*' },
);
