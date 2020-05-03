Content-Type: text/plain; charset=iso-8859-2; format=flowed
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

Pocztowe serwery kluczy OpenPGP
-------------------------------                                    
Pocztowe serwery kluczy OpenPGP pozwalaj� na wymian� kluczy publicznych
poprzez poczt� internetow�. U�ytkownicy z dost�pem do WWW mog� u�ywa�
tak�e interfejsu WWW, za� administratorzy serwer�w wymagaj�cych
cz�stego sprawdzania kluczy mog� skopiowa� ca�y keyring z serwera FTP.

Celem tej us�ugi jest u�atwienie wymiany kluczy OpenPGP mi�dzy
u�ytkowinikami. Serwer kluczy publicznych NIE GWARANTUJE prawdziwo�ci
kluczy. Do jej weryfikacji s�u�� podpisy pod kluczami.

Ka�dy serwer kluczy interpretuje polecenia zawarte w polu Subject:
otrzymywanej poczty. Polecenia NIE POWINNY by� zawarte w tre�ci listu,
gdy� zostan� wtedy zignorowane.

        To:   pgp-public-keys@keys.pl.pgp.net
        From: kowalski@gdzies.tam.pl
        Subject: help

Nowy klucz wystarczy wys�a� do JEDNEGO z serwer�w, kt�ry automatycznie
prze�le go do pozosta�ych.

�eby doda� lub zaktualizowa� klucz, wystarczy wys�a� list postaci:

        To: pgp-public-keys@keys.pl.pgp.net
        From: kowalski@gdzies.tam.pl
        Subject: add

        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: 2.6

        -----END PGP PUBLIC KEY BLOCK-----

Z�AMANE KLUCZE: Sporz�d� certyfikat anulowania klucza (sprawd� w
dokumentacji jak to zrobi�) i wy�lij klucz do serwera ponownie, wraz z
poleceniem ADD.

Oto spis wszystkich polece� akceptowanych przez serwer:

Polecenie              Rezultat
__________________________________________________________________________

HELP                   ten tekst w wersji angielskiej
HELP kraj              r�noj�zyczne wersje tego tekstu
                    (DE, EN, ES, FI, FR, HR, NO, PL)
ADD                    dodaj klucz PGP zawarty w liscie
INDEX [1]              spis kluczy PGP znanych serwerowi (-kv)
INDEX userid           spis kluczy PGP zawieraj�cych userid (-kv)
VERBOSE INDEX [1]      rozszerzony spis kluczy PGP (-kvv)
VERBOSE INDEX userid   rozszerzony spis kluczy PGP zawieraj�cych userid (-kvv)
GET [1]                ca�y keyring (w kawa�kach)
GET userid             klucz dla userid (-kxa)
MGET regexp [2,3]      klucze pasuj�ce do /regexp/
                    wyra�enie regularne musi by� przynajmniej dwuliterowe
LAST dni [3]           klucze zmienianie w ci�gu ostatnich 'dni'
__________________________________________________________________________

 1. Du�e listy
    Serwer kluczy zwraca pot�ne porcje informacji, wi�c nale�y u�ywa�
    go z rozwag�. Nie wszystkie systemy poczty elektronicznej poradz�
    sobie z du�ymi listami odsy�anymi przez serwer kluczy publicznych.
    Oto przyk�adowe rozmiary odpowiedzi serwera (w lutym 1997):
       + odpowiedzi� na "INDEX" jest list o rozmiarze 4 MB
       + "VERBOSE INDEX" zwraca list wielko�ci 8 MB
       + "GET" zwraca ca�y keyring zawieraj�cy ponad 55 tysi�cy
         kluczy, w sumie 18 MB), jako 99 list�w o wielko�ci 200 KB
         ka�dy.
    Najprawdopodobniej taka informacja b�dzie i tak ca�kowicie
    bezu�yteczna, wi�c zalecane jest u�ywanie tych polece� z
    argumentem "userid".

    UWAGA: Przy operacjach na du�ych keyringach PGP jest wyj�tkowo
    powolne. Dodanie ca�ego keyringu z serwera do prywatnego zestawu
    kluczy zaj�oby kilka dni !

    Je�li rzeczywi�cie potrzebujesz ca�ego pliku indeksowego lub
    keyringu z serwera, u�yj do tego serwera FTP (na przyk�ad
    ftp://ftp.pl.pgp.net/pub/security/pgpnet/keys/).

 2. Wyra�enia regularne w "MGET"
    Oto kilka przyk�ad�w u�ycia polecenia MGET:

    MGET wojtek             wszystkie klucze zawieraj�ce s�owo "wojtek"
    MGET icm                wszystkie klucze zawieraj�ce "icm"
    MGET E8F605A5|5F3E38F5  klucze o tych dw�ch identyfikatorach

    Wyra�enia regularne to nie to samo, co "wildcardy" znane z MS DOS.
    "*" nie oznacza "wszystko", lecz "zero lub wi�cej wyst�pie�
    poprzedniego znaku", na przyk�ad:

     a.*  oznacza wszystko rozpoczynaj�ce si� na liter� a
     ab*c pasuje do ac, abc, abbc, itd.

    Zamiast "MGET .*" u�ywaj "GET".

 3. Ograniczenia
    Niekt�re serwery kluczy maj� ograniczon� liczb� kluczy, kt�re mog�
    by� zwr�cone w odpowiedzi na polecenie "MGET" lub "LAST".
    
Nale�y u�ywa� najbli�szego serwera kluczy. Dla Polski b�dzie to
pgp-public-keys@keys.pl.pgp.net. Inne serwery kluczy publicznych:

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
    
Polski serwer FTP to ftp://ftp.pl.pgp.net/pub/pgpnet/.
