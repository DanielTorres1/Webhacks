# Web Hacks

Herrmientas web útiles para la fase de reconocimiento:

- web-buster.pl : Navegación forzada de directorios comunes, archivos de configuración, cgi, webdav, webservices, sharepoint, webserver y backup. Soporta hilos (Conexiones en paralelo)
    	  
- webData.pl: Extraer título y metadatos de sitios web.



## ¿COMO INSTALAR?

Testeado en Kali 2:

    git clone https://github.com/DanielTorres1/Webhacks
    cd Webhacks
    bash instalar.sh


## ¿COMO USAR?
**web-buster.pl**

    Uso:  
    -t : IP o dominio del servidor web 
    -p : Puerto del servidor web 
    -d : Ruta donde empezara a probar directorios 
    -j : Adicionar header ajax (xmlhttprequest) 1 para habilitar 
    -h : Número de hilos (Conexiones en paralelo. Recomendado entre 10-25) 
    -c : Cookie con la que hacer el escaneo ej: PHPSESSION=k35234325 
    -e : Busca este patron en la respuesta para determinar si es una pagina de error 404
    -s : SSL (opcional) 
    		-s 1 = SSL 
    		-s 0 = NO SSL 
    -m : Modo. Puede ser: 
    	  completo: Probara Todos los módulos (directorios,archivos, cgi, webdav,webservices, sharepoint, webserver, backup)
    	      
    Ejemplo 1:  Buscar todos los tipos de arcchivo en el directorio raiz (/) del host 192.168.0.2 en el puerto 80  con 10 hilos
    	  web-buster.pl -t 192.168.0.2 -p 80 -d / -m completo -h 10 
    
    Ejemplo 2:  Buscar backups de archivos de configuracion en el directorio /wordpress/ del host www.ejemplo.com en el puerto 443 (SSL)  
    	  web-buster.pl -t www.ejemplo.com -p 443 -d /wordpress/ -m backup -s 1 -h 20

    Ejemplo 3:  Buscar paneles de administracion en el directorio /wordpress/ del host www.ejemplo.com en el puerto 443 
    	  web-buster.pl -t www.ejemplo.com -p 443 -d /wordpress/ -m admin -h 20

**webData.pl**

    Uso:  
    -t : IP o dominio del servidor web 
    -p : Puerto del servidor web 
    -d : Ruta donde empezara a probar directorios 
    -l : Archivo donde escribira los logs 
    -e : Extraer 
    		-e parcial = titulo,metadatos,descripcion y banner 
    		-e todo = titulo,metadatos,descripcion,banner, version del lenguaje/CMS/framework usado, etc
    -s : SSL (opcional) 
    		-s 1 = SSL 
    		-s 0 = NO SSL 
    Autor: Daniel Torres Sandi 
    	Ejemplo 1:  webData.pl -t 192.168.0.2 -p 80 -e todo -l log.txt


