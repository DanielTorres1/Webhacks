#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;
use utf8;
use Text::Unidecode;
binmode STDOUT, ":encoding(UTF-8)";

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:s:e:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $ssl = $opts{'s'} if $opts{'s'};
my $extract = $opts{'e'} if $opts{'e'};

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  webData.pl -t 192.168.0.2 -p 80 -s [1/2] -e {small/all} \n"; 
  print "		-s 1 = SSL \n";
  print "		-s 2 = NO SSL \n";	
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

my $webHacks;
if ($ssl eq '')
{

	$webHacks = webHacks->new( rhost => $target,
						rport => $port,	
						max_redirect => 4,																	
					    debug => 0);	
	# Need to make a request to discover if SSL is in use
	$webHacks->dispatch(url => "http://$target:$port",method => 'GET');
}
else
{

	if ($ssl == 2) 
	{$ssl = 0} # we need to fix as SSL can not be passed as 0 (parameter)
	$webHacks = webHacks->new( rhost => $target,
						rport => $port,		
						ssl => $ssl,
						max_redirect => 4,
					    debug => 0);	
}
	   				   



my %data = $webHacks->getData();

my $title = %data{'title'};
my $poweredBy = %data{'poweredBy'};
my $Authenticate = %data{'Authenticate'};
my $geo = %data{'geo'};
my $Generator = %data{'Generator'};
my $description = %data{'description'};
my $langVersion = %data{'langVersion'};
my $redirect_url = %data{'redirect_url'};
my $author = %data{'author'};
my $proxy = %data{'proxy'};
my $type = %data{'type'};
my $server = %data{'server'};



if (! ($redirect_url =~ /http/m)){	 
	$redirect_url="";
 }




if ($extract ne 'all')
{
	print "Title: $title \n" if ($title ne '' && $title ne ' ');
	print "poweredBy $poweredBy \n" if ($poweredBy ne '' && $poweredBy ne ' ');
	print "Generator ($Generator) \n" if ($Generator ne '' && $Generator ne ' ');
	print "langVersion $langVersion \n" if ($langVersion ne '' && $langVersion ne ' ');
	print "Proxy $proxy \n" if ($proxy ne '' && $proxy ne ' ');
	print "server $server \n" if ($server ne '' && $server ne ' ');
	
	
}
else
{
	print "$title~$poweredBy~$Authenticate~$geo~$Generator~$description~$langVersion~$redirect_url~$author~$proxy~$type~$server~";
}
 

my $error_response = $webHacks->sqli_test("'");

if ($error_response ne '' && $error_response ne ' ')
	{print "PWAN SQLi! error: $error_response \n";}

