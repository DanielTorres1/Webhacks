#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  webTitle.pl -t 192.168.0.2 -p 80  \n"; 
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

	   				   
my $webHacks = webHacks->new( rhost => $target,
						rport => $port,																		
					    debug => 0);

# Need to make a request to discover if SSL is in use
$webHacks->dispatch(url => "http://$target:$port",method => 'GET');

my $title = $webHacks->getTitle();
print $title;
