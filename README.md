
# Web Hacks

Herrmientas web utiles para la fase de reconocimientos:

- web-buster.pl : Navegacion forzada de directorios
- webData.pl: Extraer titulo y metadatos.



## ¿COMO INSTALAR?

Testeado en Kali :

    git clone https://github.com/DanielTorres1/Webhacks
    cd Webhacks
    bash instalar.sh


## ¿COMO USAR?

Parametros:

    Uso:  
    -t : IP o dominio del servidor web 
    -p : Puerto del servidor web 
    -d : Ruta donde empezara a probar directorios 
    -j : Adicionar header ajax (xmlhttprequest) 1 para habilitar 
    -h : Numero de hilos (Conexiones en paralelo) 
    -c : cookie con la que hacer el escaneo ej: PHPSESSION=k35234325 
    -e : Busca este patron en la respuesta para determinar si es una pagina de error 404
    -s : SSL (opcional) 
    		-s 1 = SSL 
    		-s 0 = NO SSL 
    -m : Modo. Puede ser: 
    	  completo: Probara Todos los módulos 
    	  directorios: Probar si existen directorios comunes 
    	  archivos: Probar si existen directorios comunes 
    	  cgi: 	Probar si existen archivos cgi 
    	  webdav: Directorios webdav 
    	  webservices: Directorios webservices 
    	  sharepoint: Directorios sharepoint 
    	  webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc) 
    	  backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc) 
    	  username: Probara si existen directorios de usuarios tipo http://192.168.0.2/~daniel 
    
    Ejemplo 1:  Buscar arhivos comunes en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  con 10 hilos
    	  web-buster.pl -t 192.168.0.2 -p 80 -d / -m archivos -h 10 
    
    Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)  
    	  web-buster.pl -t 192.168.0.2 -p 443 -d /wordpress/ -m backup -s 1 -h 30


