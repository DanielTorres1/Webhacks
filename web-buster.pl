#!/usr/bin/perl
use Data::Dumper;
use webHacks;
use strict;
use Getopt::Std;

my %opts;
getopts('s:p:a:m:t:q:e:c:j:h', \%opts);

my $site = $opts{'s'} if $opts{'s'};
my $port = $opts{'p'} if $opts{'p'};
my $path = $opts{'a'} if $opts{'a'};

my $cookie = "";
$cookie = $opts{'c'} if $opts{'c'};
my $ajax = "0";
$ajax = $opts{'j'} if $opts{'j'};
my $mode = $opts{'m'} if $opts{'m'};
my $threads = $opts{'t'} if $opts{'t'};
my $quiet = $opts{'q'} if $opts{'q'};
my $error404 = $opts{'e'} if $opts{'e'};
# scan for comments

#PATTERNS = {
    # "<!%-.-%-!?>", -- HTML comment
    # "/%*.-%*/", -- Javascript multiline comment
    #"[ ,\n]//.-\n" -- Javascript one-line comment. Could be better?    
    #}
    
    # <!-- Copyright (c) Rohde & Schwarz GmbH & Co. KG Munich Germany All Rights Reserved.-->
    #<meta name="description" content="WVC80N">
    
# ADD FUNCTIONALITY 
#   Source code comments
    #Errors (MySQL errors, warnings, fatals, etc)
    #Linux file paths    


$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my $banner = <<EOF;
      ___  __      __        __  ___  ___  __  
|  | |__  |__)    |__) |  | /__`  |  |__  |__) 
|/\\| |___ |__)    |__) \\__/ .__/  |  |___ |  \\ v1.0                                              

Autor: Daniel Torres Sandi
EOF


sub usage { 
  
  print $banner;
  print "Uso:  \n";  
  print "-s : IP o dominio del servidor web \n";
  print "-p : Puerto del servidor web \n";
  print "-a : Ruta donde empezara a probar directorios \n";
  print "-j : Adicionar header ajax (xmlhttprequest) 1 para habilitar \n";
  print "-t : Numero de hilos (Conexiones en paralelo) \n";
  print "-c : cookie con la que hacer el escaneo ej: PHPSESSION=k35234325 \n";
  print "-e : Busca este patron en la respuesta para determinar si es una pagina de error 404\n";
  print "-m : Modo. Puede ser: \n";
  print "	  directorios: Probar si existen directorios comunes \n";
  print "	  archivos: Probar si existen directorios comunes \n";
  print "	  cgi: 	Probar si existen archivos cgi \n";
  print "	  webdav: Directorios webdav \n";
  print "	  webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc) \n";
  print "	  backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc) \n";
  print "	  username: Probara si existen directorios de usuarios tipo http://192.168.0.2/~daniel \n";
  print "	  completo: Probara Todo lo anterior \n";
  print "\n";
  print "Ejemplo 1:  Buscar arhivos comunes en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  con 10 hilos\n";
  print "	  web-buster.pl -s 192.168.0.2 -p 80 -a / -m archivos -t 10 \n";
  print "\n";
  print "Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)  \n";
  print "	  web-buster.pl -s 192.168.0.2 -p 443 -a /wordpress/ -m backup -t 30\n";
  print "\n";  
}	

# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

if ($quiet ne 1)
{print $banner,"\n";}


my $webHacks ;
if ($error404 eq '')
{

$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,								
						cookie => $cookie,
						ajax => $ajax,
						max_redirect => 0,
					    debug => 0);
	
}
else
{
$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,
						error404 => $error404,
						cookie => $cookie,
						ajax => $ajax,
						max_redirect => 0,
					    debug => 0);
}

# Need to make a request to discover if SSL is in use
$webHacks->dispatch(url => "http://$site:$port$path",method => 'GET');

# fuzz with common files names
if ($mode eq "archivos" or $mode eq "completo"){	
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/files.txt");	
	print "\n";
}

# fuzz with common directory names
if ($mode eq "directorios" or $mode eq "completo" ){	
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/directorios.txt");	
	print "\n";
}

# fuzz with common cgi files names
if ($mode eq "cgi" or $mode eq "completo"){
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/cgi.txt");	
	print "\n";
}

# fuzz with common server files names
if ($mode eq "webserver" or $mode eq "completo"){	
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");	
	print "\n";
}

# fuzz with backup names (add .bak, .swp, etc)
if ($mode eq "backup" or $mode eq "completo"){	
	my $status = $webHacks->backupbuster("/usr/share/webhacks/wordlist/configFiles.txt");	
	print "\n";
}

# fuzz with user names 
if ($mode eq "username" or $mode eq "completo"){	
	my $status = $webHacks->userbuster("/usr/share/webhacks/wordlist/nombres.txt");	
	print "\n";
}

# fuzz with webdav
if ($mode eq "webdav" or $mode eq "completo"){	
	my $status = $webHacks->userbuster("/usr/share/webhacks/wordlist/webdav.txt");	
	print "\n";
}

