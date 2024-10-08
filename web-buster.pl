#!/usr/bin/perl
use Data::Dumper;
use webHacks;
use strict;
use Getopt::Std;

my %opts;
getopts('t:p:d:r:j:h:c:s:m:i:o:u:q:e:', \%opts);


my $site = $opts{'t'} if $opts{'t'};
my $port = $opts{'p'} if $opts{'p'};
my $path = $opts{'d'} if $opts{'d'};
my $max_redirect = $opts{'r'} if $opts{'r'};

my $cookie = "";
$cookie = $opts{'c'} if $opts{'c'};
my $custom_dir = $opts{'u'} if $opts{'u'};
my $proto = $opts{'s'};
my $mostrarTodo = $opts{'o'};
my $ajax = "0";
$ajax = $opts{'j'} if $opts{'j'};
my $mode = $opts{'m'} if $opts{'m'};
my $threads = $opts{'h'} if $opts{'h'};
my $quiet = $opts{'q'} if $opts{'q'};
my $timeout = $opts{'i'} if $opts{'i'};
my $error404 = $opts{'e'} if $opts{'e'};
my $debug=0;


$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

sub usage { 
  print "Uso:  \n";  
  print "-t : IP o dominio del servidor web \n";
  print "-p : Puerto del servidor web \n";
  print "-r : Seguir n redirecciones \n";
  print "-u : Directorio personalizado \n";
  print "-i : Time out (segundos) \n";
  print "-d : Ruta donde empezara a probar directorios \n";
  print "-j : Adicionar header ajax (xmlhttprequest) 1 para habilitar \n";
  print "-h : Numero de hilos (Conexiones en paralelo) \n";
  print "-c : cookie con la que hacer el escaneo ej: PHPSESSION=k35234325 \n";
  print "-e : Busca este patron en la respuesta para determinar si es una pagina de error 404\n";
  print "-s : SSL (opcional) \n";
  print "		-s https = SSL \n";
  print "		-s http = NO SSL \n";	
  print "-o : Definir que resultados mostrar (opcional) \n";
  print "		-o 1 = Mostrar todo inclusive errores 404, 500, etc \n";
  print "		-o 0 = Mostrar solo 200 OK \n";	
  print "-m : Modo. Puede ser: \n";
  print "	  folders: Probar si existen directorios comunes \n";
  print "	  files: Probar si existen directorios comunes \n";
  print "	  cgi: 	Probar si existen archivos cgi \n";
  print "	  graphQL: 	Probar si existe un endpoint de graphQL \n";
  print "	  php: 	Probar si existen archivos php \n";
  print "	  perl:	Probar si existen archivos perl \n";
  print "	  webdav: Directorios webdav \n";
  print "	  webservices: Directorios webservices \n";  
  print "	  archivosPeligrosos: Archivos peligrosos \n";  
  print "	  default: Archivos por defecto \n";    
  print "	  information: php info files, error logs \n";  
  print "	  webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc) \n";
  print "	  backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc) \n";
  print "	  \n\tCombinaciones:\n";  
  print "	  apacheServer: Probara Todos los modulos de Apache \n";
  print "	  tomcatServer: Probara Todos los modulos de Tomcat \n";
  print "	  iisServer: Probara Todos los modulos de IIS \n";
  print "\n";
  print "Ejemplo 1:  Buscar arhivos comunes en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  con 10 hilos\n";
  print "	  web-buster.pl -r 1 -t 192.168.0.2 -p 80 -d / -m archivos -h 10 \n";
  print "\n";
  print "Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)  \n";
  print "	  web-buster.pl -r 1 -t 192.168.0.2 -p 443 -d /wordpress/ -m backup -s https -h 30\n";  
  print "\n";
  print "Ejemplo 3:  Buscar archivos/directorios del host 192.168.0.2 (apache) en el puerto 443 (SSL)  \n";
  print "	  web-buster.pl -r 1 -t 192.168.0.2 -p 443 -d / -m apache -s https -h 30\n";  
  print "\n";  
}	

# Print help message if required
if (!(%opts)) {
	usage();
	exit 0;
}

if ($timeout eq '')
{
	$timeout = 15;
}

if ($quiet ne 1)
{print $banner,"\n";}

$mostrarTodo = 1 if ($mostrarTodo eq '');
print "mostrarTodo $mostrarTodo" if ($debug);

$max_redirect = 0 if ($max_redirect eq '');				    
my $webHacks ;

if($error404 eq '' and $proto eq '')
{

	$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,						
						cookie => $cookie,
						timeout => $timeout,
						ajax => $ajax,						
						max_redirect => $max_redirect,
					    debug => $debug,
					    mostrarTodo => $mostrarTodo);	

# Need to make a request to discover if SSL is in use
$webHacks->dispatch(url => "http://$site:$port$path",method => 'GET');
}

if($error404 ne '' and $proto eq '' )
{
	
	$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,
						error404 => $error404,						
						cookie => $cookie,
						timeout => $timeout,
						ajax => $ajax,						
						max_redirect => $max_redirect,
					    debug => $debug,
					    mostrarTodo => $mostrarTodo);	

# Need to make a request to discover if SSL is in use
print "Descubrir si es HTTP o HTTPS";
$webHacks->dispatch(url => "http://$site:$port$path",method => 'GET');					    
}

if($proto ne '' and $error404 eq '' )
{
	$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,
						proto => $proto,
						cookie => $cookie,
						timeout => $timeout,
						ajax => $ajax,						
						max_redirect => $max_redirect,
					    debug => $debug,
					    mostrarTodo => $mostrarTodo);	
}

if ($error404 ne ''  and $proto ne '' )
{	
	$webHacks = webHacks->new( rhost => $site,
						rport => $port,
						path => $path,
						threads => $threads,
						error404 => $error404,
						proto => $proto,
						cookie => $cookie,
						timeout => $timeout,
						ajax => $ajax,						
						max_redirect => $max_redirect,
					    debug => $debug,
					    mostrarTodo => $mostrarTodo);	
}


# especific dic
if ($mode eq "custom"){	
	$webHacks->dirbuster($custom_dir);	
	print "\n";
}

# registration URL 
if ($mode eq "registroHabilitado"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/registroHabilitado.txt");	
	print "\n";
}


if ($mode eq "graphQL" ){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/graphQL.txt");	
	print "\n";
}

if ($mode eq "files" ){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/files.txt");	
	print "\n";
}

# fuzz with admin
if ($mode eq "admin"){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/admin.txt");	
	print "\n";
}

# fuzz with archivosPeligrosos
if ($mode eq "archivosPeligrosos"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt");	
	print "\n";
}

# fuzz with sap
if ($mode eq "sap"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/sap.txt");	
	print "\n";
}

# fuzz with common directory names
if ($mode eq "folders"){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/directorios.txt");	
	print "\n";
}

# fuzz with common cgi files names
if ($mode eq "cgi" ){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/cgi.txt");	
	print "\n";
}

# fuzz with common server files names
if ($mode eq "webserver"){			
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");	
	print "\n";
}


# fuzz with webservices
if ($mode eq "webservices" ){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webservices.txt");	
	print "\n";
}


# fuzz with backdoors apache
if ($mode eq "backdoorApache"){
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/backdoorsApache.txt");	
	print "\n";
}

# fuzz with backdoors IIS
if ($mode eq "backdoorIIS"){
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/backdoorsIIS.txt");	
	print "\n";
}

#########################
# fuzz with files (with extension)
if ($mode eq "php" ){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","php");			
	print "\n";
}


# php 
if ($mode eq "information"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/divulgacionInformacion.txt");	
	#$webHacks->contentBuster("/usr/share/webhacks/wordlist/divulgacionInformacion.txt","HTTP_USER_AGENT");	
	print "\n";
}


if ($mode eq "default"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/archivosDefecto.txt");	
	#$webHacks->contentBuster("/usr/share/webhacks/wordlist/divulgacionInformacion.txt","HTTP_USER_AGENT");	
	print "\n";
}

##########################
# fuzz with iis
if ($mode eq "iis"){		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/iis.txt");		
	print "\n";
}

# sharepoint 
if ($mode eq "sharepoint"){	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/sharepoint.txt");	
	print "\n";
}


# fuzz with aspx files
if ($mode eq "aspx"){			
	#$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","asp");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","aspx");		
	print "\n";
}

#########################
# fuzz with tomcat
if ($mode eq "tomcat"){			
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/tomcat.txt");		
	print "\n";
}
# fuzz with jsp
if ($mode eq "jsp"  ){				
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","jsp");			
	print "\n";
}

# fuzz with perl
if ($mode eq "perl"  ){					
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","pl");	
	print "\n";
}
#######################


#
if ($mode eq "apacheServer" ){			
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/files.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/graphQL.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/admin.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/registroHabilitado.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt");		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/directorios.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/cgi.txt");		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/backdoorsApache.txt");		
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","php");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","htm");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","html");		
	print "\n";
}


#file.ext~, file.ext.bak, file.ext.tmp, file.ext.old, file.bak, file.tmp and file.old
# fuzz with backup names (add .bak, .swp, etc)
if ($mode eq "backupApache"){			
	$webHacks->backupbuster("/usr/share/webhacks/wordlist/configFilesApache.txt");	
	print "\n";
}

# fuzz with backup names (add .bak, .swp, etc)
if ($mode eq "backupIIS" ){			
	$webHacks->backupbuster("/usr/share/webhacks/wordlist/configFilesIIS.txt");	
	print "\n";
}



if ($mode eq "iisServer" ){				
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/admin.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/registroHabilitado.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/directorios.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/backdoorsIIS.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/sharepoint.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webservices.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","asp");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","aspx");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","htm");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","html");	
	print "\n";
}


if ($mode eq "tomcatServer" ){				
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/admin.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt");
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/directorios.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/webserver.txt");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","jsp");	
	$webHacks->dirbuster("/usr/share/webhacks/wordlist/files.txt","htm");		
	print "\n";
}


