# Web Hacks

Navegacion forzada (web fuzzing)
Password por defecto de interfaces web


## ¿COMO INSTALAR?

Testeado en Kali y ubuntu. Simplemente ejecuta:

`bash install.sh`


## ¿COMO USAR?

Parametros:

-t : IP del servidor web 
-p : Puerto del servidor web 
-a : Ruta donde empezara a probar directorios 
-m : Modo. Puede ser: 
	  directorios: Probar si existen directorios comunes 
	  archivos: Probar si existen archivos comunes 
	  cgi: 	Probar si existen archivos cgi 
	  webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc) 
	  backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc) 
	  username: Probara si existen directorios de usuarios tipo http://192.168.0.2/~daniel 

Ejemplo 1:  Buscar arhivos comunes en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  
	  dirbuster.pl -t 192.168.0.2 -p 80 -a / -m directorios

Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)  
	  dirbuster.pl -t ejemplo.com -p 443 -a /wordpress/ -m backup
