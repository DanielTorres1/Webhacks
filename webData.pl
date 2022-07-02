#!/usr/bin/perl
use Data::Dumper;
require webHacks;
use strict;
use Getopt::Std;
use utf8;
use Text::Unidecode;
binmode STDOUT, ":encoding(UTF-8)";

#$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opts;
getopts('t:p:s:e:i:d:l:r:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $proto = $opts{'s'};
my $path = $opts{'d'};
my $redirect = $opts{'r'};
my $sqli = $opts{'i'} if $opts{'i'};
my $extract = $opts{'e'} if $opts{'e'};
my $log_file = $opts{'l'} if $opts{'l'};
my $debug = 0;

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
						max_redirect => $redirect,						
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
						max_redirect => $redirect,
					    debug => $debug);	
}
	   				   



my %data = $webHacks->getData(log_file => $log_file);

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
my $status = %data{'status'};
my $wappalyzer;

$wappalyzer=`docker run -it wappalyzer/cli $proto://$target:$port$path --pretty | wappalyzer-parser.py`; 

# 	print "Title: $title \n" if ($title ne '' && $title ne ' ');
# 	print "poweredBy $poweredBy \n" if ($poweredBy ne '' && $poweredBy ne ' ');
# 	print "Generator ($Generator) \n" if ($Generator ne '' && $Generator ne ' ');
# 	print "langVersion $langVersion \n" if ($langVersion ne '' && $langVersion ne ' ');
# 	print "Proxy $proxy \n" if ($proxy ne '' && $proxy ne ' ');
# #	print "redirect_url $server \n" if ($redirect_url ne '' && $redirect_url ne ' ');
# 	print "server $server \n" if ($server ne '' && $server ne ' ');
	
if($status =~ /Name or service not known/m){	 
	$status =~ /Can't connect to (.*?):/;
	my $domain = $1; 

	my @domain_array = split /\./, $domain;
	my $length = scalar @domain_array;
	if ($length > 2)			
	{
		$domain = @domain_array[1].'.'.@domain_array[2];
		print "Name or service not known~$domain";
	}
	else
		{print "Name or service not known~$domain";}
	
 } 
 else
 {
	print "$title~$server~$status~$poweredBy~$Authenticate~$geo~$Generator~$description~$langVersion~$redirect_url~$author~$proxy~$type || $wappalyzer";
 }

#if ($sqli)
#{
	#my $error_response = $webHacks->sqli_test("'");

	#if ($error_response ne '' && $error_response ne ' ')
		#{print "PWAN SQLi! error: $error_response \n";}

#}
