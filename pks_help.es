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
  German:    F�r eine deutschsprachige Fassung dieses Textes senden Sie
             eine Mail mit dem Subject "HELP DE" an die folgende Adresse
             pgp-public-keys@keys.de.pgp.net oder URL:
             http://www.pgp.net/pgp/email-help-de.html
  English:   For an English version of this message, send an e-mail with a
             subject line of "HELP" to pgp-public-keys@keys.pgp.net, or
             access the URL http://www.pgp.net/pgpnet/email-help-en.html
  Spanish:   Para obtener una versi�n en castellano de este texto, env�e
             un mail a pgp-public-keys@keys.nl.pgp.net con el "Subject"
             HELP ES
  Finnish:   Saadaksesi taman tekstin suomeksi, laheta osoitteeseen
             pgp-public-keys@keys.nl.pgp.net tyhja viesti, jonka
             Subject-kentta on "HELP FI".
  French:    Pour une version fran�aise de �e texte, envoyez un
             message au sujet de "HELP FR" � pgp-public-keys@keys.ch.pgp.net
  Croatian:  Za hrvatsku verziju ovoga teksta posaljite poruku koja ce u
             Subject imati "HELP HR" na adresu pgp-public-keys@keys.nl.pgp.net
  Japanese:  Nihongo no setumei ga hosii baai wa Subject: ni "HELP JA"
             to kaite, pgp-public-keys@keys.pgp.net ni e-mail.
  Korean:    �Ʒ��� ������ �ѱ۷� ���÷��� ����(Subject)�� "HELP KR" ��
             ���ڿ����� pgp-public-keys@keys.kr.pgp.net ���� �����ֽʽÿ�.
  Polish:    Zeby uzyskac polska wersje tej strony, wyslij list z linia
             "HELP PL" w polu Subject na adres
             pgp-public-keys@keys.pl.pgp.net lub zajrzyj pod URL
             http://www.pgp.net/pgpnet/email-help-pl.html
  Portuguese:Para obter uma vers�o em portugu�s deste texto, deve enviar um
             mail para pgp-public-keys@keys.pt.pgp.net com o "Subject"
             HELP PT
  Norwegian: For aa faa dette dokumentet paa norsk, send "HELP NO" til
             pgp-public-keys@keys.nl.pgp.net
  Swedish:   For a Swedish version of this message, send an e-mail with a
             subject line of "HELP SE" to pgp-public-keys@keys.se.pgp.net, or
	     access the URL http://www.pgp.net/pgpnet/email-help-se.html
  Chinese:   ����o���@���媩 PGP ���A�����ѽu�W���U����, �� E-mail ��
	     pgp-public-keys@keys.tw.pgp.net, �� Subject: ���� "HELP TW" �Y�i.
]

Servidores de Claves OpenPGP por correo electr�nico
---------------------------------------------------

Existen servidores p�blicos de claves de OpenPGP accesibles por medio del 
correo electr�nico, que permiten intercambiar claves p�blicas usando 
los mecanismos de correo de Internet y de UUCP. Aquellos que tengan 
acceso al WWW quiz�s prefieran usar la interfaz WWW disponible a 
trav�s del URL http://www.pgp.net/pgpnet/www-key.html, y los responsables 
de sistemas de instalaciones que puedan desear realizar b�squedas 
frecuentes pueden preferir copiar el llavero entero del servidor 
an�nimo de FTP en ftp://ftp.pgp.net/pub/pgp/keys/

Este servicio existe �nicamente para ayudar a los usuarios de OpenPGP a 
intercambiar claves. En NING�N CASO intenta garantizar que la clave en 
cuesti�n es v�lida; para obtener esta clase de seguridad debe 
recurrirse a las firmas de la clave.

Cada servidor de claves procesa las solicitudes de servicio en forma 
de mensajes de correo. Las instrucciones al servidor deben aparecer en
la linea del Subject: (Asunto:)
-------------=======
N�tese bien que NO deben incluirse en el cuerpo del mensaje.
---------------====-----------------------------------------

        To: pgp-public-keys@keys.pgp.net
        From: fulanito@mi.dominio
        Subject: help

Es suficiente con enviar su clave p�blica a UN servidor. Despu�s de 
procesarla, el servidor enviar� autom�ticamente su solicitud de alta a 
los dem�s servidores de forma autom�gica.

Por ejemplo, para agregar su clave al servidor, o para actualizarla si 
ya est� all�, env�e un mensaje parecido al siguiente a cualquier 
servidor:

        To: pgp-public-keys@keys.pgp.net
        From: fulanito@mi.dominio
        Subject: add

        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: 2.6

        <bla bla bla>
        -----END PGP PUBLIC KEY BLOCK-----

CLAVES COMPROMETIDAS: Cree un certificado de anulaci�n (lea la 
documentaci�n del PGP sobre c�mo hacer �sto, bajo el ep�grafe "Key 
Revocation Certificate") y env�e su clave una vez m�s al servidor, 
usando la instrucci�n ADD.

Las instrucciones v�lidas son:

Instrucci�n		Significa
--------------------- -------------------------------------------------
HELP                   Le devuelve este mensaje de ayuda
HELP idioma            Ayuda en el idioma elegido (uno de entre DE, ES,
                       ES, FI, FR, HR, NO)
ADD                    A�ade su clave p�blica PGP (la clave va el cuerpo
                       del mensaje)
INDEX idusuario        Listado de todas las claves que contiene las
                       palabras indicadas en idusuario
VERBOSE INDEX idusuario  Lista extendida de las claves que contiene las
                       palabras indicadas en idusuario
GET idusuario          Obtener las claves que concuerdan con idusuario
LAST dias              Obtener las claves modificadas en los �ltimos
                       'dias' d�as
------------------------------------------------------------------------

LIMITACIONES:

La mayor�a de los servidores tienen un l�mite en el n�mero de clave que
devuelven en las consultas, de forma que no le saturen con la respuesta
si comete un error al escribit (la base de datos completa de los
servidores excede los 2 GB de tama�o).

Si *REALMENTE* necesita todo el fichero de indice o el anillo de claves,
*POR FAVOR*, desc�rguelo por ftp de un servidor de claves como
'ftp://ftp.pgp.net/pub/pgp/keys/' o uno de los servidores nacionales.

NOTA: PGP es extremadamente lento cuando trabaja con anillos de claves
      grandes. Le costar� *MESES* a�adir todo el anillo del
      servidor en su anillo de claves local.

DIRECCIONES A USAR;

Los usuarios deber�an normalmente usar la direcci�n de correo 
electr�nico `pgp-public-keys@keys.pgp.net', o acceder a sus servidores 
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

para acceder a la interfaz de correo electr�nico,  
`ftp://ftp.pgp.net/pub/pgp/' para acceder por FTP y
`http://www.pgp.net/pgpnet/' para el acceso por WWW.

Se recomienda a los usuarios la utilizaci�n de las direcciones 
"*.pgp.net" mencionadas m�s arriba puesto que son estables y 
confiables.
