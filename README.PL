#!/usr/bin/perl

use strict;
use warnings;
use Pod::Readme;

my $pod_readme = Pod::Readme->new(
    input_file        => 'lib/Monitoring/Plugin/REST.pm',
    translate_to_file => 'README',
    translation_class => 'Pod::Simple::Text',
);

$pod_readme->run;
