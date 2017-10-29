#module-starter --module=webHacks --author="Daniel Torres" --email=daniel.torres@owasp.org
# May 27 2017
# web Hacks
package webHacks;
our $VERSION = '1.0';
use Moose;
use Text::Table;
use Data::Dumper;
use LWP::UserAgent;
use HTTP::Cookies;
use URI::Escape;
use HTTP::Request;
use HTTP::Response;
use HTML::Scrubber;
use Parallel::ForkManager;
use Net::SSL (); # From Crypt-SSLeay
use Term::ANSIColor;
use utf8;
use Text::Unidecode;
binmode STDOUT, ":encoding(UTF-8)";


no warnings 'uninitialized';

$Net::HTTPS::SSL_SOCKET_CLASS = "Net::SSL"; # Force use of Net::SSL for proxy compatibility

{
has 'rhost', is => 'rw', isa => 'Str',default => '';	
has 'rport', is => 'rw', isa => 'Str',default => '80';	
has 'path', is => 'rw', isa => 'Str',default => '/';	
has 'ssl', is => 'rw', isa => 'Str',default => '';	
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
has headers  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_headers' );
has browser  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_browser' );

########### scan directories #######       
sub dirbuster
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $path = $self->path;
my $error404 = $self->error404;
my $threads = $self->threads;
my $ssl = $self->ssl;
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


print "ssl in dirbuster $ssl \n" if ($debug);

my $lines = `wc -l $url_file | cut -d " " -f1`;
$lines =~ s/\n//g;
my $time = int($lines/600);

print color('bold blue');
print "######### Usando archivo: $url_file ##################### \n";
print "Configuracion : Hilos: $threads \t SSL:$ssl \t Ajax: $ajax \t Cookie: $cookie\n";
print "Tiempo estimado en probar $lines URLs : $time minutos\n\n";
print color('reset');

my $result_table = Text::Table->new(
        "STATUS", "  URL", "\t\t\t\t RISKY METHODS"
);
    
print $result_table;

foreach my $file (@links) {
    $pm->start and next; # do the fork   
    $file =~ s/\n//g; 	
	#Adicionar backslash
	#if (! ($file =~ /\./m)){	 
	if ($url_file =~ "directorios"){	 
		$file = $file."/";
	}

	my $url;
	if ($ssl)
		{$url = "https://".$rhost.":".$rport.$path.$file;}
	else
		{$url = "http://".$rhost.":".$rport.$path.$file;}   
        
	#print "getting $url \n";
	
	
	##############  thread ##############
	my $response = $self->dispatch(url => $url,method => 'GET',headers => $headers);
	my $status = $response->status_line;
	my $decoded_content = $response->decoded_content;
		 
	if ($error404 ne '')		
		{			
			if($decoded_content =~ /$error404/m){	
				$status="404"; 
			}
		}
	
	if($status !~ /404|500|302|303|301|503|400/m){		
		my @status_array = split(" ",$status);	
		my $current_status = $status_array[0];
		my $response2 = $self->dispatch(url => $url,method => 'OPTIONS',headers => $headers);
		my $options = " ";
		$options = $response2->{_headers}->{allow};	
		$options =~ s/GET|HEAD|POST|OPTIONS//g; # delete safe methods	
		$options =~ s/,,//g; # delete safe methods	
		print "$current_status\t$url\t$options \n";
		#$result_table->add($url,$status,$options);			
	}
	
	#if($status =~ /302|301/m){		
		
		#my $response_headers = $response->headers_as_string;
		#my ($location) = ($response_headers =~ /Location:(.*?)\n/i);
		#print "location $location \n" if ($debug);

		#if ( length($location) > 10 )
			#{print "$status\t$url;$location\n";}		
		
		#$result_table->add($url,$status,$options);			
	#}
	##############	
   $pm->finish; # do the exit in the child process
  
  }
  $pm->wait_all_children;

}




#search for directories like   192.168.0.1/~username
sub userbuster
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $path = $self->path;
my $ssl = $self->ssl;
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
my $time = int($lines/600);

print color('bold blue');
print "######### Usando archivo: $url_file ##################### \n";
print "Configuracion : Hilos: $threads \t SSL:$ssl \t Ajax: $ajax \t Cookie: $cookie\n";
print "Tiempo estimado en probar $lines URLs : $time minutos\n\n";
print color('reset');

my $result_table = Text::Table->new(
        "STATUS", "  URL", "\t\t\t\t RISKY METHODS"
);
    
print $result_table;    

foreach my $file (@links) {
    $pm->start and next; # do the fork   
    $file =~ s/\n//g; 	

	my $url;
	if ($ssl)
		{$url = "https://".$rhost.":".$rport.$path."~".$file."/";}
	else
		{$url = "http://".$rhost.":".$rport.$path."~".$file."/";}  
        
	#print "getting $url \n";
	##############  thread ##############
	my $response = $self->dispatch(url => $url,method => 'GET',headers => $headers);
	my $status = $response->status_line;
	my $decoded_content = $response->decoded_content;
		 
	if ($error404 ne '')		
		{			
			if($decoded_content =~ /$error404/m){	
				$status="404"; 
			}
		}
		
	if($status !~ /404|500|302|303|301|503|400/m){		
		my @status_array = split(" ",$status);	
		my $current_status = $status_array[0];
		my $response2 = $self->dispatch(url => $url,method => 'OPTIONS',headers => $headers);
		my $options = " ";
		$options = $response2->{_headers}->{allow};	
		$options =~ s/GET|HEAD|POST|OPTIONS//g; # delete safe methods	
		$options =~ s/,,//g; # delete safe methods	
		print "$current_status\t$url\t$options \n";
		#$result_table->add($url,$status,$options);			
	}
	##############	
   $pm->finish; # do the exit in the child process
  }
  $pm->wait_all_children;   
}



#search for backupfiles
sub backupbuster
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $path = $self->path;
my $ssl = $self->ssl;
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
print "Configuracion : Hilos: $threads \t SSL:$ssl \t Ajax: $ajax \t Cookie: $cookie\n";
print "Tiempo estimado en probar $lines archivos de backup : $time minutos\n\n";
print color('reset');

    
my $result_table = Text::Table->new(
        "STATUS", "  URL", "\t\t\t\t RISKY METHODS"
);

print $result_table;

foreach my $file (@links) 
{
	my @backups = ("FILE","FILE.bak","FILE-bak", "FILE~", "FILE.save", "FILE.swp", "FILE.old","Copy of FILE","FILE (copia 1)",".FILE.swp");
	$file =~ s/\n//g; 	
	#print "file $file \n";
	my $url;

	foreach my $backup_file (@backups) {			
		$backup_file =~ s/FILE/$file/g;    		
		
		if ($ssl)
			{$url = "https://".$rhost.":".$rport.$path.$backup_file;}
		else
			{$url = "http://".$rhost.":".$rport.$path.$backup_file;}
				    
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
		if($status !~ /404|500|302|303|301|503|400/m){				
			#$result_table->add($url,$status);	
			print "$current_status\t$url\n";
		}		
		$pm->finish; # do the exit in the child process		   
	}# end foreach backupname
	$pm->wait_all_children; 
} # end foreach file
}




sub defaultPassword
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $ssl = $self->ssl;

my %options = @_;
my $software = $options{ software };
my $passwords_file = $options{ passwords_file };


print color('bold blue') if($debug);
print "######### Testendo: $software ##################### \n\n" if($debug);
print color('reset') if($debug);


my $url;
if ($ssl)
  {$url = "https://".$rhost.":".$rport;}
else
  {$url = "http://".$rhost.":".$rport;}

if ($software eq "ZKSoftware")
{
		
	open (MYINPUT,"<$passwords_file") || die "ERROR: Can not open the file $passwords_file\n";	
	while (my $password=<MYINPUT>)
	{ 
		$password =~ s/\n//g; 	
		my $hash_data = {'username' => 'administrator', 
				'userpwd' => $password
				};	
	
		my $post_data = convert_hash($hash_data);
		
		my $response = $self->dispatch(url => $url."/csl/check",method => 'POST',post_data =>$post_data, headers => $headers);
		my $decoded_response = $response->decoded_content;
		my $status = $response->status_line;
		
		if ($status =~ /200/m)
		{
			if (! ($decoded_response =~ /Error/m)){	 
			print "ZKSoftware: Password found! (administrator:$password)\n";
			last;
			}							
		}	
		
	}
	close MYINPUT;	

}#ZKSoftware
}




sub getData
{
my $self = shift;
my $headers = $self->headers;
my $debug = $self->debug;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $ssl = $self->ssl;


my $url;
if ($ssl)
  {$url = "https://".$rhost.":".$rport;}
else
  {$url = "http://".$rhost.":".$rport;}


my $response = $self->dispatch(url => $url, method => 'GET', headers => $headers);
my $decoded_response = $response->decoded_content;

#<meta http-equiv="Refresh" content="0; URL=/page.cgi?page=status">
$decoded_response =~ /meta http-equiv="Refresh" content="0; URL=(.*?)"/i;
my $redirect_url = $1; 

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


$redirect_url =~ s/\'//g;  
print "redirect_url $redirect_url \n" if ($debug);

if($redirect_url =~ /http/m ){	 
	$response = $self->dispatch(url => $redirect_url, method => 'GET', headers => $headers);
	$decoded_response = $response->decoded_content; 	 
 }  
elsif ($redirect_url ne '' )
{	
	my $final_url = $url.$redirect_url;
	print "final_url $final_url \n" if ($debug);
	$response = $self->dispatch(url => $final_url, method => 'GET', headers => $headers);
	$decoded_response = $response->decoded_content; 	 
}


my $response_headers = $response->headers_as_string;
my $final_url = $response->request->uri;
print "final_url $final_url \n" if ($debug);
$self->final_url($final_url);

$decoded_response = $response_headers."\n".$decoded_response;

$decoded_response =~ s/<title>\n/<title>/g; 
$decoded_response =~ s/<title>\r\n/<title>/g; 

#open (SALIDA,">response.html") || die "ERROR: No puedo abrir el fichero google.html\n";
#print SALIDA $decoded_response;
#close (SALIDA);


my ($poweredBy) = ($decoded_response =~ /X-Powered-By:(.*?)\n/i);
if ($poweredBy eq '')
	{	
	if($decoded_response =~ /laravel_session/m){$poweredBy="Laravel";} 			
	}

print "poweredBy $poweredBy \n" if ($debug);

# ($hours, $minutes, $second) = ($time =~ /(\d\d):(\d\d):(\d\d)/);
my ($title) = ($decoded_response =~ /<title(.*?)<\/title>/i);

if ($title eq '')
	{($title) = ($decoded_response =~ /<title(.*?)\n/i);}

if ($title eq '')
	{($title) = ($decoded_response =~ /Title:(.*?)\n/i);}

$title =~ s/>//g; 
$title = only_ascii($title);


#<meta name="geo.placename" content="Quillacollo" />
my ($geo) = ($decoded_response =~ /name="geo.placename" content="(.*?)"/i);
print "geo $geo \n" if ($debug);

#<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
my ($Generator) = ($decoded_response =~ /name="Generator" content="(.*?)"/i);
print "Generator $Generator \n" if ($debug);

#<meta name="Version" content="10_1_7-52331">
my ($Version) = ($decoded_response =~ /name="Version" content="(.*?)"/i);
print "Version $Version \n" if ($debug);
$Generator = $Generator." ".$Version;

my ($description) = ($decoded_response =~ /name="description" content="(.*?)"/i);
if ($description eq '')
	{($description) = ($decoded_response =~ /X-Meta-Description:(.*?)\n/i);}
$description = only_ascii($description);	
print "description $description \n" if ($debug);


#<meta name="author" content="Instituto Nacional de Estadística - Centro de Desarrollo de Redatam">
my ($author) = ($decoded_response =~ /name="author" content="(.*?)"/i);
if ($author eq '')
	{($author) = ($decoded_response =~ /X-Meta-Author:(.*?)\n/i);}
$author = only_ascii($author);
print "author $author \n" if ($debug);


my ($langVersion) = ($decoded_response =~ /X-AspNet-Version:(.*?)\n/i);
print "langVersion $langVersion \n" if ($debug);

my ($proxy) = ($response_headers =~ /Via:(.*?)\n/i);
print "proxy $proxy \n" if ($debug);

my ($server) = ($response_headers =~ /Server:(.*?)\n/i);
print "server $server \n" if ($debug);

#WWW-Authenticate: Basic realm="Broadband Router"
my ($Authenticate) = ($response_headers =~ /WWW-Authenticate:(.*?)\n/i);
print "Authenticate $Authenticate \n" if ($debug);


my $type;
if($decoded_response =~ /GASOLINERA/m)
	{$type="GASOLINERA";} 		


 my %data = (
            "poweredBy" => $poweredBy,
            "title" => $title,
            "Authenticate" => $Authenticate,
            "geo" => $geo,
            "Generator" => $Generator,
            "description" => $description,
            "langVersion" => $langVersion,
            "redirect_url" => $redirect_url,
            "author" => $author,
            "proxy" => $proxy,
            "type" => $type,
            "server" => $server,
            
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
#print $final_content;
        
$self->html($final_content);
return %data;
		
}



sub sqli_test
{
my $self = shift;
my $headers = $self->headers;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $debug = $self->debug;
my $ssl = $self->ssl;
my $html = $self->html;
my $url = $self->final_url;
#print "html  $html  \n" ;	
print "Tessting SQLi\n" if ($debug );
my ($inyection)=@_;

my @sqlerrors = ( 'error in your SQL syntax',
 'mysql_fetch',
 'sqlsrv_fetch_object',
 "Unclosed quotation mark after the character",
 'num_rows',
 "syntax error at or near",
 "SQL command not properly ended",
 'ORA-01756',
 "quoted string not properly terminated",
 'Error Executing Database Query',
 "Failed to open SQL Connection",
 'SQLServer JDBC Driver',
 'Microsoft OLE DB Provider for SQL Server',
 'Unclosed quotation mark',
 'ODBC Microsoft Access Driver',
 'Microsoft JET Database',
 'Error Occurred While Processing Request',
 'Server Error',
 'Microsoft OLE DB Provider for ODBC Drivers error',
 'Invalid Querystring',
 'OLE DB Provider for ODBC',
 'VBScript Runtime',
 'ADODB.Field',
 'BOF or EOF',
 'ADODB.Command',
 'JET Database',
 'mysql_fetch_array()',
 'Syntax error',
 'mysql_numrows()',
 'GetArray()',
 'FetchRow()');
 
my $error_response="";
my $pwned;
 
$html =~ /<form action="(.*?)"/;			
my $action = $1; 
print "action $action \n" if ($debug );

my $post_data = "";
while($html =~ /<input name="(.*?)"/g) 
{    
    $post_data = $post_data.$1."=XXX&";
}
chop($post_data); # delete last character (&)

$post_data =~ s/XXX/$inyection/g; 
print "post_data  $post_data  \n" if ($debug );

if ($post_data ne '')
{
	my $final_url = $url.$action;	
	print "final_url  $final_url  \n" if ($debug );
	$headers->header("Content-Type" => 'application/x-www-form-urlencoded');	
	my $response = $self->dispatch(url => $final_url, method => 'POST',post_data =>$post_data, headers => $headers);
	my $decoded_response = $response->decoded_content;
	
	#open (SALIDA,">sqli.html") || die "ERROR: No puedo abrir el fichero google.html\n";
	#print SALIDA $decoded_response;
	#close (SALIDA);   

	###### chech error in response #####
	foreach (@sqlerrors)
	{	
		 if($decoded_response =~ /$_/i)
		 {
			$error_response = $_;			
			$pwned=1;		
			last;
		  }
		else
			{$error_response = ""}
	}	
}
		

return($error_response);
}

################################### build objects ########################

################### build headers object #####################
sub _build_headers {   
#print "building header \n";
my $self = shift;
my $debug = $self->debug;
my $headers = HTTP::Headers->new;


my @user_agents=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/28.0.1500.71 Chrome/28.0.1500.71 Safari/537.36",
			  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36",
			  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:23.0) Gecko/20100101 Firefox/23.0",
			  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31",
			  "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36");			   
			  
my $user_agent = @user_agents[rand($#user_agents+1)];    
print "user_agent $user_agent \n" if ($debug);

$headers->header('User-Agent' => "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"); 
$headers->header('Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'); 
$headers->header('Connection' => 'close'); 
$headers->header('Cache-Control' => 'max-age=0'); 
$headers->header('DNT' => '1'); 
#$headers->header('Content-Type' => 'application/x-www-form-urlencoded');
#$headers->header('Accept-Encoding' => [ HTTP::Message::decodable() ]);


return $headers; 
}


###################################### internal functions ###################


# remve acents and ñ
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

return $text;
}


#Convert a hash in a string format used to send POST request
sub convert_hash
{
my ($hash_data)=@_;
my $post_data ='';
foreach my $key (keys %{ $hash_data }) {    
    my $value = $hash_data->{$key};
    $post_data = $post_data.uri_escape($key)."=".$value."&";    
}	
chop($post_data); # delete last character (&)
 #$post_data = uri_escape($post_data);
return $post_data;
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
   #$response = $self->browser->post($url,Content_Type => 'multipart/form-data', Content => $post_data, $headers);
   $response = $self->browser->request($req);    
  } 

if ($method eq 'POST_FILE')
  { 
	my $post_data = $options{ post_data };         	    
	$headers->header('Content_Type' => 'application/atom+xml');
    my $req = HTTP::Request->new(POST => $url, $headers);
    $req->content($post_data);
    #$response = $self->browser->post( $url, Content_Type => 'application/atom+xml', Content => $post_data, $headers);                 
    $response = $self->browser->request($req);    
  }  
      
  
return $response;
}

################### build browser object #####################	
sub _build_browser {    

my $self = shift;
my $rhost = $self->rhost;
my $rport = $self->rport;
my $ssl = $self->ssl;

my $debug = $self->debug;
my $proxy_host = $self->proxy_host;
my $proxy_port = $self->proxy_port;
my $proxy_user = $self->proxy_user;
my $proxy_pass = $self->proxy_pass;
my $proxy_env = $self->proxy_env;

my $max_redirect = $self->max_redirect;

print "building browser \n" if ($debug);


my $browser = LWP::UserAgent->new;

$browser->timeout(13);
$browser->cookie_jar(HTTP::Cookies->new());
$browser->show_progress(1) if ($debug);
$browser->max_redirect($max_redirect);


if ($ssl eq '')
{
	print "Detecting SSL \n" if ($debug);
	my $ssl_output = `get_ssl_cert.py $rhost $rport 2>/dev/null`;
	if($ssl_output =~ /CN/m)
		{$self->ssl(1);print "SSL detected \n" if ($debug);}
	else
		{$self->ssl(0); print "NO SSL detected \n" if ($debug);}
}

print "proxy_env $proxy_env \n" if ($debug);

if ( $proxy_env eq 'ENV' )
{
print "set ENV PROXY \n";
$Net::HTTPS::SSL_SOCKET_CLASS = "Net::SSL"; # Force use of Net::SSL
$ENV{HTTPS_PROXY} = "http://".$proxy_host.":".$proxy_port;

}
elsif (($proxy_user ne "") && ($proxy_host ne ""))
{
 $browser->proxy(['http', 'https'], 'http://'.$proxy_user.':'.$proxy_pass.'@'.$proxy_host.':'.$proxy_port); # Using a private proxy
}
elsif ($proxy_host ne "")
   { $browser->proxy(['http', 'https'], 'http://'.$proxy_host.':'.$proxy_port);} # Using a public proxy
 else
   { 
      $browser->env_proxy;} # No proxy       

return $browser;     
}
    
}
1;
