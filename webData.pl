#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;
use utf8;
use Text::Unidecode;
binmode STDOUT, ":encoding(UTF-8)";

$ENV{OPENSSL_CONF} = '/usr/share/lanscanner/sslv1.conf';
$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = "Net::SSL";

my %opts;
getopts('t:p:s:e:i:d:l:r:h:v', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $proto = $opts{'s'};
my $path = $opts{'d'};
my $max_redirect = $opts{'r'} if $opts{'r'};
my $sqli = $opts{'i'} if $opts{'i'};
my $extract = $opts{'e'} if $opts{'e'};
my $log_file = $opts{'l'} if $opts{'l'};
my $debug = $opts{'v'} if $opts{'v'};

$max_redirect = 0 if ($max_redirect eq '');
$debug = 0 if ($debug eq '');

sub usage { 
  
  print "Uso:  \n";  
  print "-t : IP o dominio del servidor web \n";
  print "-p : Puerto del servidor web \n";
  print "-d : Ruta donde empezara a probar directorios \n";
  print "-l : Archivo donde escribira los logs \n";
  print "-r : Cuantas redirecciones seguir\n";
  print "-e : Extraer \n";
  print "		-e parcial = titulo,metadatos,descripcion y banner \n";
  print "		-e todo = titulo,metadatos,descripcion,banner, version del lenguaje/CMS/framework usado, etc\n";	
  print "-s : SSL (opcional) \n";
  print "		-s http = NO SSL \n";
  print "		-s https = SSL \n";	
  
  print "Autor: Daniel Torres Sandi \n";
  print "	Ejemplo 1:  webData.pl -t ejemplo.com -p 80 -d / -e todo -l log.txt -r 0 \n"; 
  print "	Ejemplo 1:  webData.pl -t 192.168.0.2 -p 80 -d /phpmyadmin/ -e todo -l log.txt -r 4 \n"; 
	  
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

my $webHacks;
if ($proto eq '')
{

	$webHacks = webHacks->new( rhost => $target,
						rport => $port,	
						path => $path,	
						max_redirect => $max_redirect,						
					    debug => $debug);	
	# Need to make a request to discover if SSL is in use
	$webHacks->dispatch(url => "http://$target:$port",method => 'GET');
}
else
{
	
	$webHacks = webHacks->new( rhost => $target,
						rport => $port,	
						path => $path,		
						proto => $proto,						
						max_redirect => $max_redirect,
					    debug => $debug);	
}
	   				   



my %data = $webHacks->getData(log_file => $log_file);
my $title = %data{'title'};
my $server = %data{'server'};
my $status = %data{'status'};
my $redirect_url = %data{'redirect_url'};
my $last_url = %data{'last_url'};
my $newdomain = %data{'newdomain'};
my $vulnerability = %data{'vulnerability'};
my $poweredBy = %data{'poweredBy'};
my $wappalyzer = '';

$vulnerability="vulnerabilidad=$vulnerability" if (length($vulnerability)>1);	

my $domain; 

if($status =~ /Name or service not known/m){	 
	$status =~ /Can't connect to (.*?):/;
	$domain = $1; 
	my @domain_array = split /\./, $domain;
	my $length = scalar @domain_array;
	if ($length > 2)			
	{
		$domain = @domain_array[1].'.'.@domain_array[2];
		
	}	
	
 } 

if ($newdomain ne '')		
	{print "$title~$server~$status~$redirect_url~$last_url~$poweredBy~$vulnerability~^$wappalyzer^Dominio identificado^$newdomain";}
else
{
	if ($domain ne '')
		{print "^$wappalyzer^Dominio identificado^$domain";}
	else
		{print "$title~$server~$status~$redirect_url~$last_url~$poweredBy~$vulnerability~^$wappalyzer";}
}


 
#if ($sqli)
#{
	#my $error_response = $webHacks->sqli_test("'");

	#if ($error_response ne '' && $error_response ne ' ')
		#{print "PWAN SQLi! error: $error_response \n";}

#}
