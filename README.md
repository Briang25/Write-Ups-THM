# Write-Ups-THM
Resolución de maquinas vulnerables y CTF's de TryHackme

## Nebula.io

¿Qué tipo se solicitud (flag) manda Nmap para realizar un descubrimiento de host?

SYN

he usado el comando de Nmap:

```bash
nmap -sn ip_machine
```

¿Si descubrimos el host a través de ARP cuál es el primer length que se envía al puerto más pequeño?

60

he usado el comando de Nmap

```bash
nmap -PR -sn ip_machine
```

¿Qué puerto tiene abierto por UDP?

puertos abiertos por UDP: 53 y 68

para descubrir el puerto abierto por udp he utilizado el comando.

```bash
sudo nmap -PU ip_machine -p-
```

---

¿Qué tiempo de vida (TTL) tiene el puerto UDP en nuestro host?

el TTL que tiene el puerto UDP es de 64

he utilizado el comando:

```bash
sudo nmap -PP -sn ip_machine
```

---

¿Qué puerto tiene corriendo el servicio domain?

esta corriendo en el puerto 53

he usado el comando grande de Nmap:

```bash
sudo nmap -A -sV -vv -sC 10.10.243.162 -oX informe_nmap.xml --stylesheet "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -p-
```

---

¿Cuántos puertos TCP tiene cerrados?

tiene cerrados 65532 puertos

comando utilizado: 

```bash
sudo nmap -A -sV -vv -sC 10.10.243.162 -oX informe_nmap.xml --stylesheet "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -p-
```

---

¿Cuál es el bind.version?

9.9.5-3ubuntu0.19-Ubuntu

comando utilizado:

```bash
sudo nmap -sX -A -sV -vv -sC 10.10.243.162 -oX informe_nmap.xml --stylesheet "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -p-
```

---

¿Cuál es el título de la web?

Bluffer V.0.1a

Lo he encontrado en el scan de nmap

---

¿Por qué puerto corre el servicio licensedaemon?

1986

también encontrado en nmap

---

¿Qué versión de SSH tiene Nebula?

```bash
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
```

encontrado en el Nmap

---

¿Cuál es la Public Key de ED25519?

encontrada en el Nmap

```bash
b1:7b:06:a9:49:85:1e:2a:0a:de:71:9d:8b:50:d3:4a
```

---

¿Qué servicio es vulnerable a ataques de man-in-the-middle?

SSH

aqui he realizado un scaneo avanzado en Nessus para encontrar vulnerabilidades

---

¿Cuál es el CVSS asociado a la vulnerabilidad?

 5,9 se ve en Nessus

---

¿Cómo se llama popularmente el ataque?

Terrapin Attack

comprobado en la web

---

¿Cuál es el CVE asociado a la vulnerabilidad más alta de SSH?

CVE-2023-48795

también encontrada en Nessus

---

¿Cuál es CVSS más bajo que has encontrado?

2,1 (Nessus)

---

¿Cómo se llama la vulnerabilidad?

ICMP Timestamp Request Remote Date Disclosure

---

¿Qué Plugin la ha detectado?

10114 (Nessus)

¿Cuál es el código de verificación de google site?

"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"

lo he encontrado  con el siguiente comando:

```bash
nslookup -type=TXT nebula.io 10.10.166.43
Server:     	10.10.166.43

Address:    	10.10.166.43#53

nebula.io   	text = "nebula-verification=examplecode123"

nebula.io   	text = "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
```

---

¿A qué IP apunta el dominio de nebula.io?

en esta parte estuve algo atascado ya que estaba realizando mal la consulta del dominio, lo estaba realizando al dominio nebula pero no lo había agregado al archivo de hosts en la maquina, asi que los datos que me daban no eran los correctos.

después de agregar el dominio y la ip al archivo host han salido bien las consultas.

```bash
etc/host

[nebula.io](http://nebula.io)        ip_machine
```

¿Cuál es el valor del registro AAAA?

¿Cuál es el TTL del ftp?

Nebula se conecta a través de VPN por la ip…

Nebula se conecta al correo electrónico por la ip…

En el registro PTR, ¿cuál es el prefijo inverso?

¿Con quien contactarías en caso de necesitar ayuda con el soporte?

¿Cuál es la información del servidor de nebula.io?

Encuentra la flag

¿Cuál es la FLAG de nebula.io?

**todas esta preguntas se responden con la siguiente consulta:**

```bash
dig axfr @10.10.129.142 nebula.io

; <<>> DiG 9.20.7-1-Debian <<>> @10.10.129.142 nebula.io axfr
; (1 server found)
;; global options: +cmd
nebula.io.          	7200	IN  	SOA 	ns1.nebula.io. admin.nebula.io. 2023102501 604800 86400 2419200 604800
nebula.io.          	300 	IN  	HINFO   "Nebula Server" "Linux"
nebula.io.          	301 	IN  	TXT 	"nebula-verification=examplecode123"
nebula.io.          	301 	IN  	TXT 	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
nebula.io.          	7200	IN  	MX  	0 mail.nebula.io.
nebula.io.          	7200	IN  	MX  	0 ASPMX.L.GOOGLE.COM.
nebula.io.          	7200	IN  	MX  	10 ALT1.ASPMX.L.GOOGLE.COM.
nebula.io.          	7200	IN  	MX  	10 ALT2.ASPMX.L.GOOGLE.COM.
nebula.io.          	7200	IN  	MX  	20 ASPMX2.GOOGLEMAIL.COM.
nebula.io.          	7200	IN  	MX  	20 ASPMX3.GOOGLEMAIL.COM.
nebula.io.          	7200	IN  	MX  	20 ASPMX4.GOOGLEMAIL.COM.
nebula.io.          	7200	IN  	MX  	20 ASPMX5.GOOGLEMAIL.COM.
nebula.io.          	86400   IN  	NS  	ns1.nebula.io.
nebula.io.          	86400   IN  	NS  	ns2.nebula.io.
nebula.io.          	7200	IN  	A   	192.168.150.144
_sip._tcp.nebula.io.	14000   IN  	SRV 	0 5 5060 sip.nebula.io.
144.150.168.192.IN-ADDR.ARPA.nebula.io. 7200 IN PTR www.nebula.io.
bluffer.nebula.io.  	7200	IN  	TXT 	"BLUFFER{S3cr3t_DNS_Tr4nsfer_Flag}"
contact.nebula.io.  	2592000 IN  	TXT 	"Para soporte, contactar a admin@nebula.io o llamar al +1 123 4567890"
deadbeef.nebula.io. 	7201	IN  	AAAA	dead:beef::1
ftp.nebula.io.      	7200	IN  	A   	192.168.150.180
mail.nebula.io.     	7200	IN  	A   	192.168.150.146
ns1.nebula.io.      	86400   IN  	A   	192.168.150.144
ns2.nebula.io.      	86400   IN  	A   	192.168.150.145
office.nebula.io.   	7200	IN  	A   	192.0.2.10
sip.nebula.io.      	7200	IN  	A   	192.168.150.147
vpn.nebula.io.      	7200	IN  	A   	198.51.100.10
www.nebula.io.      	7200	IN  	A   	192.168.150.144
xss.nebula.io.      	300 	IN  	TXT 	"user : bluffer"
nebula.io.          	7200	IN  	SOA 	ns1.nebula.io. admin.nebula.io. 2023102501 604800 86400 2419200 604800
;; Query time: 48 msec
;; SERVER: 10.10.129.142#53(10.10.129.142) (TCP)
;; WHEN: Thu Apr 17 02:09:25 EDT 2025
;; XFR size: 30 records (messages 1, bytes 961)

```

---

---

en esta parte del reto de nebula he optado por utilizar el comando de gobuster después de hacer una investigación y repaso de gobuster en tryhackme

```bash
gobuster vhost -u http://10.10.138.35 -w /usr/share/wordlists/dirb/common.txt --exclude-length 250-320 
```

con ese comando logre encontrar el otro dominio de nebula

```bash
Found: admin.nebula.io Status: 200
```

¿Cuál es el PIN?

despues de agregar este nuevo dominio de nuebula con su ip al archivo de hosts puedo abrir esta nueva pagina web.

```bash
etc/host

[nebula.io](http://nebula.io/)        ip_machine
admin.nebula.io  ip_machine
```

al inspeccionar la pagina de [admin.nebula.io] he encontrado un archivo.zip que he procedido a descargármelo y descomprimirlo, en este se encontraba un archivo con un texto cifrado el cual lo copie y lo he pegado en una pagina de descifrado el cual me dio como resultado el numero: 

al introducir el pin ingreso aun apartado en el cual se parece a un Siem en el cual tengo que responder algunas preguntas.

---

---

¿Cuál es la IP y puerto ha generado la alerta?

la ip que ha generado la alerta es: 143.110.250.149 

---

¿Cuál es su ISP?

su ISP es: **China Mobile communications Corporation**

---

¿Cómo se llama el Ejecutivo de ventas?

el ejecutivo de ventas se llama **Joan Ribas**

---

¿Qué IP fue añadida a la lista negra el 30 de Junio de 2024?

fue añadida la ip: **212.38.99.12**

---

¿Cuál ha sido el resultado?

GFCS{ANALISTA-LEVEL-1}

---

¿Cuál es la FLAG?
FLAG{GOOD-J08!}

---

¿Cuál es la contraseña?

después de realizar el reto del siem nos ha dado una lista de posibles contraseñas las cuales las he agregado a un .txt para poder utilizarlas con hydra

```bash
hydra -L  bluffer -P nebula.txt -t12 ssh://10.10.227.92:1986
```
---

¿Por qué puerto te has conectado?

1986 que es el ssh

---

¿A qué servidor "REMOTO" se conecta el juego?

10.10.6PmP.@*x4

---

al conectarme al puerto ssh con el usuario y contraseña llego a una shell la cual es rbash,no puedo usar la mayoría de comandos, es una shell restrictiva.

hay instrucciones de usar algunos comandos, START_BLUFFER activaba un juego y otro comando dice OPEN_SMB al escribir esto en la shell y dar intro procede a activar el servicio SMB

---

al hacer un Nmap descubro que el servicio que se ha activado corre en el puerto **44544** el servicio es samba el cual tiene una vulnerabilidad la cual tiene un **9,8  su CVE-2017-7494** fue descubierta en 2017 y es conocida como SambaCry.

teniendo estos datos he decidido usar metasploit. así que procedo a ejecutar meta exploit y ejecuto el comando para realizar una búsqueda.

```bash
search CVE-2017-7494
```

esto me da como resultado una lista en la cual encuentro este exploit que es el que he elegido para explotar este servicio:

```bash
0   exploit/linux/samba/is_known_pipename  2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
```

he introducido los datos que me indica el exploit para su configuración, como lo es el RHOSTS y el RPORT.

procedo a correr el exploit y con esto ya estaría dentro de la maquina como :

```bash
root@Nebula-server
```

el nombre del anfitrión seria Nebula.server

luego he usado el siguiente comando para saber cual es la información del sistema operativo:

```bash
uname -a
Nebula-server 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

---

estando dentro de la maquina procedo a ver que hay en el archivo shadow

```bash
cat shadow
```

el cual me muestra Cuantos usuarios hay, ademas me muestra que dos usuarios tienen un hash root y guakamole

el hash para el usuario de root es:

```bash
root:$6$dTV9ZkDw$ZULnb36XSMz1fv4LzsGXZnq7FpRx3H6v3CUmD/iySvY4M/9lzVGUVv81ChJsasATlegYJLib8Ciw1/fowpi2s0
```

---

---

la persona que gestiona el usuario guakamole se llama **David Kline**

y el usuario que reporta los errores del sistema se llama **Gnats**


---

Conociendo estos datos he decidido usar John the Ripper para descifrar los hash de estos 2 usuarios

he introducido el hash a un archivo.txt y he usado el comando de John the Ripper para descrifrarlo y asi saber su contraseña la cual es: kamikaze2

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt pass.txt
```


