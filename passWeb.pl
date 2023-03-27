#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('s:t:p:m:d:u:c:f:', \%opts);
#print(%opts);

my $proto = $opts{'s'} if $opts{'s'};
my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $module = $opts{'m'} if $opts{'m'};
my $path = $opts{'d'} if $opts{'d'};
my $user = $opts{'u'} if $opts{'u'};
my $password = $opts{c} || '';
my $passwords_file = $opts{f} || '';


sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  passWeb.pl -s http -t 192.168.0.2 -p 80 -d / -m ZKSoftware -u administrator -f passwords.txt \n"; 
  print "	Ejemplo 2:  passWeb.pl -s https -t 192.168.0.2 -p 443 -d /admin/ -m phpmyadmin -u root -f passwords.txt \n"; 
  print "	Ejemplo 3:  passWeb.pl -s http -t 192.168.0.2 -p 80 -d / -m PRTG -u prtgadmin -f passwords.txt  \n"; 
  print "	Ejemplo 4:  passWeb.pl -s http -t 192.168.0.2 -p 80 -d / -m zimbra -u juan.perez -f passwords.txt  \n"; 
  print "	Ejemplo 5:  passWeb.pl -s http -t 192.168.0.2 -p 80 -d / -m zte -u user -f passwords.txt  \n"; 
  print "	Ejemplo 6:  passWeb.pl -s http -t 192.168.0.2 -p 8081 -d / -m pentaho -u admin -f top.txt \n"; 
  print "	Ejemplo 6:  passWeb.pl -s http -t 192.168.0.2 -p 80 -d / -m ZTE-ONT-4G -u admin -c admin \n"; 

}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

	   				   
my $webHacks = webHacks->new( rhost => $target,
						rport => $port,
            proto => $proto,
						max_redirect => 4,
					    debug => 0);
              
$webHacks->passwordTest( module => $module, path => $path, user => $user, passwords_file => $passwords_file, password => $password)
