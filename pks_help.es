Content-Type: text/plain; charset=iso-8859-1; format=flowed
Content-Transfer-Encoding: 8bit
Content-Disposition: inline

[
  Czech:     Pro ziskani ceske verze tohoto textu poslete prosim e-mail se
             "Subject" radkou "HELP CZ" na adresu
             pgp-public-keys@keys.cz.pgp.net, nebo pristupte na URL
             http://www.pgp.net/pgpnet/email-help-cz.html
  Danish:    For at faa en dansk version af denne text skal du sende en
             e-mail med en subject-tekst: "HELP DK" til
             pgp-public-keys@keys.dk.pgp.net eller slaa op paa URL
             http://www.pgp.net/pgpnet/email-help-dk.html
  German:    Für eine deutschsprachige Fassung dieses Textes senden Sie
             eine Mail mit dem Subject "HELP DE" an die folgende Adresse
             pgp-public-keys@keys.de.pgp.net oder URL:
             http://www.pgp.net/pgp/email-help-de.html
  English:   For an English version of this message, send an e-mail with a
             subject line of "HELP" to pgp-public-keys@keys.pgp.net, or
             access the URL http://www.pgp.net/pgpnet/email-help-en.html
  Spanish:   Para obtener una versión en castellano de este texto, envíe
             un mail a pgp-public-keys@keys.nl.pgp.net con el "Subject"
             HELP ES
  Finnish:   Saadaksesi taman tekstin suomeksi, laheta osoitteeseen
             pgp-public-keys@keys.nl.pgp.net tyhja viesti, jonka
             Subject-kentta on "HELP FI".
  French:    Pour une version française de çe texte, envoyez un
             message au sujet de "HELP FR" à pgp-public-keys@keys.ch.pgp.net
  Croatian:  Za hrvatsku verziju ovoga teksta posaljite poruku koja ce u
             Subject imati "HELP HR" na adresu pgp-public-keys@keys.nl.pgp.net
  Japanese:  Nihongo no setumei ga hosii baai wa Subject: ni "HELP JA"
             to kaite, pgp-public-keys@keys.pgp.net ni e-mail.
  Korean:    ¾Æ·¡ÀÇ ³»¿ëÀ» ÇÑ±Û·Î º¸½Ã·Á¸é Á¦¸ñ(Subject)ÀÌ "HELP KR" ÀÎ
             ÀüÀÚ¿ìÆíÀ» pgp-public-keys@keys.kr.pgp.net À¸·Î º¸³»ÁÖ½Ê½Ã¿À.
  Polish:    Zeby uzyskac polska wersje tej strony, wyslij list z linia
             "HELP PL" w polu Subject na adres
             pgp-public-keys@keys.pl.pgp.net lub zajrzyj pod URL
             http://www.pgp.net/pgpnet/email-help-pl.html
  Portuguese:Para obter uma versão em português deste texto, deve enviar um
             mail para pgp-public-keys@keys.pt.pgp.net com o "Subject"
             HELP PT
  Norwegian: For aa faa dette dokumentet paa norsk, send "HELP NO" til
             pgp-public-keys@keys.nl.pgp.net
  Swedish:   For a Swedish version of this message, send an e-mail with a
             subject line of "HELP SE" to pgp-public-keys@keys.se.pgp.net, or
	     access the URL http://www.pgp.net/pgpnet/email-help-se.html
  Chinese:   ¹ï¨ú±o¦¹¤@¤¤¤åª© PGP ¦øªA¾¹´£¨Ñ½u¤W»²§U»¡©ú, ½Ð E-mail µ¹
	     pgp-public-keys@keys.tw.pgp.net, ©ó Subject: µù©ú "HELP TW" §Y¥i.
]

Servidores de Claves OpenPGP por correo electrónico
---------------------------------------------------

Existen servidores públicos de claves de OpenPGP accesibles por medio del 
correo electrónico, que permiten intercambiar claves públicas usando 
los mecanismos de correo de Internet y de UUCP. Aquellos que tengan 
acceso al WWW quizás prefieran usar la interfaz WWW disponible a 
través del URL http://www.pgp.net/pgpnet/www-key.html, y los responsables 
de sistemas de instalaciones que puedan desear realizar búsquedas 
frecuentes pueden preferir copiar el llavero entero del servidor 
anónimo de FTP en ftp://ftp.pgp.net/pub/pgp/keys/

Este servicio existe únicamente para ayudar a los usuarios de OpenPGP a 
intercambiar claves. En NINGÚN CASO intenta garantizar que la clave en 
cuestión es válida; para obtener esta clase de seguridad debe 
recurrirse a las firmas de la clave.

Cada servidor de claves procesa las solicitudes de servicio en forma 
de mensajes de correo. Las instrucciones al servidor deben aparecer en
la linea del Subject: (Asunto:)
-------------=======
Nótese bien que NO deben incluirse en el cuerpo del mensaje.
---------------====-----------------------------------------

        To: pgp-public-keys@keys.pgp.net
        From: fulanito@mi.dominio
        Subject: help

Es suficiente con enviar su clave pública a UN servidor. Después de 
procesarla, el servidor enviará automáticamente su solicitud de alta a 
los demás servidores de forma automágica.

Por ejemplo, para agregar su clave al servidor, o para actualizarla si 
ya está allí, envíe un mensaje parecido al siguiente a cualquier 
servidor:

        To: pgp-public-keys@keys.pgp.net
        From: fulanito@mi.dominio
        Subject: add

        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: 2.6

        <bla bla bla>
        -----END PGP PUBLIC KEY BLOCK-----

CLAVES COMPROMETIDAS: Cree un certificado de anulación (lea la 
documentación del PGP sobre cómo hacer ésto, bajo el epígrafe "Key 
Revocation Certificate") y envíe su clave una vez más al servidor, 
usando la instrucción ADD.

Las instrucciones válidas son:

Instrucción		Significa
--------------------- -------------------------------------------------
HELP                   Le devuelve este mensaje de ayuda
HELP idioma            Ayuda en el idioma elegido (uno de entre DE, ES,
                       ES, FI, FR, HR, NO)
ADD                    Añade su clave pública PGP (la clave va el cuerpo
                       del mensaje)
INDEX idusuario        Listado de todas las claves que contiene las
                       palabras indicadas en idusuario
VERBOSE INDEX idusuario  Lista extendida de las claves que contiene las
                       palabras indicadas en idusuario
GET idusuario          Obtener las claves que concuerdan con idusuario
LAST dias              Obtener las claves modificadas en los últimos
                       'dias' días
------------------------------------------------------------------------

LIMITACIONES:

La mayoría de los servidores tienen un límite en el número de clave que
devuelven en las consultas, de forma que no le saturen con la respuesta
si comete un error al escribit (la base de datos completa de los
servidores excede los 2 GB de tamaño).

Si *REALMENTE* necesita todo el fichero de indice o el anillo de claves,
*POR FAVOR*, descárguelo por ftp de un servidor de claves como
'ftp://ftp.pgp.net/pub/pgp/keys/' o uno de los servidores nacionales.

NOTA: PGP es extremadamente lento cuando trabaja con anillos de claves
      grandes. Le costará *MESES* añadir todo el anillo del
      servidor en su anillo de claves local.

DIRECCIONES A USAR;

Los usuarios deberían normalmente usar la dirección de correo 
electrónico `pgp-public-keys@keys.pgp.net', o acceder a sus servidores 
nacionales usando una de entre:

	pgp-public-keys@keys.at.pgp.net
	pgp-public-keys@keys.au.pgp.net
	pgp-public-keys@keys.cz.pgp.net
	pgp-public-keys@keys.de.pgp.net
	pgp-public-keys@keys.es.pgp.net
	pgp-public-keys@keys.fi.pgp.net
	pgp-public-keys@keys.hr.pgp.net
	pgp-public-keys@keys.hu.pgp.net
	pgp-public-keys@keys.kr.pgp.net
	pgp-public-keys@keys.nl.pgp.net
	pgp-public-keys@keys.no.pgp.net
	pgp-public-keys@keys.pl.pgp.net
	pgp-public-keys@keys.se.pgp.net
	pgp-public-keys@keys.tw.pgp.net
	pgp-public-keys@keys.uk.pgp.net
	pgp-public-keys@keys.us.pgp.net

para acceder a la interfaz de correo electrónico,  
`ftp://ftp.pgp.net/pub/pgp/' para acceder por FTP y
`http://www.pgp.net/pgpnet/' para el acceso por WWW.

Se recomienda a los usuarios la utilización de las direcciones 
"*.pgp.net" mencionadas más arriba puesto que son estables y 
confiables.
