#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:s:f:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $software = $opts{'s'} if $opts{'s'};
my $passwords_file = $opts{'f'} if $opts{'f'};

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  passWeb.pl -t 192.168.0.2 -p 80 -s ZKSoftware -f passwords.txt \n"; 
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

$webHacks->defaultPassword( software => $software, passwords_file => $passwords_file)



  # Max 30 processes for parallel download
  #my $pm = new Parallel::ForkManager(3); 

  #foreach my $url (@links) {
    #$pm->start and next; # do the fork
    #print "getting .. \n";
	#get($url);
    #$pm->finish; # do the exit in the child process
#  }
  #$pm->wait_all_children;


