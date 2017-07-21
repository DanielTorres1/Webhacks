#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:s:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $software = $opts{'s'} if $opts{'s'};

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  defaultPass.pl -t 192.168.0.2 -p 80 -s ZKSoftware \n"; 
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

	   				   
my $webHacks = webHacks->new( rhost => $target,
						rport => $port,																		
					    debug => 0);

$webHacks->defaultPassword($software)



  # Max 30 processes for parallel download
  #my $pm = new Parallel::ForkManager(3); 

  #foreach my $url (@links) {
    #$pm->start and next; # do the fork
    #print "getting .. \n";
	#get($url);
    #$pm->finish; # do the exit in the child process
#  }
  #$pm->wait_all_children;


