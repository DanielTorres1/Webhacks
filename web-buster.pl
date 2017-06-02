#!/usr/bin/perl
use Data::Dumper;
use webHacks;
use strict;
use Getopt::Std;

my %opts;
getopts('t:p:a:m:q:h', \%opts);

my $target = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $path = $opts{'a'} if $opts{'a'};
my $mode = $opts{'m'} if $opts{'m'};
my $quiet = $opts{'q'} if $opts{'q'};
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
  
  print "Uso:  \n";  
  print "-t : IP del servidor web \n";
  print "-p : Puerto del servidor web \n";
  print "-a : Ruta donde empezara a probar directorios \n";
  print "-m : Modo. Puede ser: \n";
  print "	  normal: Probar si existen directorios comunes \n";
  print "	  cgi: 	Probar si existen archivos cgi \n";
  print "	  webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc) \n";
  print "	  backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc) \n";
  print "	  username: Probara si existen directorios de usuarios tipo http://192.168.0.2/~daniel \n";
  print "\n";
  print "Ejemplo 1:  Buscar arhivos comunes en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  \n";
  print "	  dirbuster.pl -t 192.168.0.2 -p 80 -a / -m normal\n";
  print "\n";
  print "Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)  \n";
  print "	  dirbuster.pl -t 192.168.0.2 -p 443 -a /wordpress/ -m backup\n";
  print "\n";  
}	

# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

if ($quiet ne 1)
{print $banner,"\n";}


my $webHacks = webHacks->new( rhost => $target,
						rport => $port,
						path => $path,						
					    debug => 0);

# Discover if SSL is in use
$webHacks->dispatch(url => "http://$target:$port$path",method => 'GET');

# fuzz with common files names
if ($mode eq "normal"){
	print "### Buscando directorios #### \n";
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/spanish.txt");	
	print "\n";
}

# fuzz with common cgi files names
if ($mode eq "cgi"){
	print "### Buscando archivos cgi #### \n";
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/cgi.txt");	
	print "\n";
}

# fuzz with common server files names
if ($mode eq "webserver"){
	print "### Buscando archivos webserver #### \n";
	my $status = $webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");	
	print "\n";
}

# fuzz with backup names (add .bak, .swp, etc)
if ($mode eq "backup"){
	print "### Buscando backups #### \n";
	my $status = $webHacks->backupbuster("/usr/share/webhacks/wordlist/files.txt");	
	print "\n";
}

# fuzz with user names 
if ($mode eq "username"){
	print "### Buscando directorios de usuarios #### \n";
	my $status = $webHacks->userbuster("/usr/share/webhacks/wordlist/nombres.txt");	
	print "\n";
}
