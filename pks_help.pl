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

Pocztowe serwery kluczy OpenPGP
-------------------------------                                    
Pocztowe serwery kluczy OpenPGP pozwalaj± na wymianê kluczy publicznych
poprzez pocztê internetow±. U¿ytkownicy z dostêpem do WWW mog± u¿ywaæ
tak¿e interfejsu WWW, za¶ administratorzy serwerów wymagaj±cych
czêstego sprawdzania kluczy mog± skopiowaæ ca³y keyring z serwera FTP.

Celem tej us³ugi jest u³atwienie wymiany kluczy OpenPGP miêdzy
u¿ytkowinikami. Serwer kluczy publicznych NIE GWARANTUJE prawdziwo¶ci
kluczy. Do jej weryfikacji s³u¿± podpisy pod kluczami.

Ka¿dy serwer kluczy interpretuje polecenia zawarte w polu Subject:
otrzymywanej poczty. Polecenia NIE POWINNY byæ zawarte w tre¶ci listu,
gdy¿ zostan± wtedy zignorowane.

        To:   pgp-public-keys@keys.pl.pgp.net
        From: kowalski@gdzies.tam.pl
        Subject: help

Nowy klucz wystarczy wys³aæ do JEDNEGO z serwerów, który automatycznie
prze¶le go do pozosta³ych.

¯eby dodaæ lub zaktualizowaæ klucz, wystarczy wys³aæ list postaci:

        To: pgp-public-keys@keys.pl.pgp.net
        From: kowalski@gdzies.tam.pl
        Subject: add

        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: 2.6

        -----END PGP PUBLIC KEY BLOCK-----

Z£AMANE KLUCZE: Sporz±d¼ certyfikat anulowania klucza (sprawd¼ w
dokumentacji jak to zrobiæ) i wy¶lij klucz do serwera ponownie, wraz z
poleceniem ADD.

Oto spis wszystkich poleceñ akceptowanych przez serwer:

Polecenie              Rezultat
__________________________________________________________________________

HELP                   ten tekst w wersji angielskiej
HELP kraj              ró¿nojêzyczne wersje tego tekstu
                    (DE, EN, ES, FI, FR, HR, NO, PL)
ADD                    dodaj klucz PGP zawarty w liscie
INDEX [1]              spis kluczy PGP znanych serwerowi (-kv)
INDEX userid           spis kluczy PGP zawieraj±cych userid (-kv)
VERBOSE INDEX [1]      rozszerzony spis kluczy PGP (-kvv)
VERBOSE INDEX userid   rozszerzony spis kluczy PGP zawieraj±cych userid (-kvv)
GET [1]                ca³y keyring (w kawa³kach)
GET userid             klucz dla userid (-kxa)
MGET regexp [2,3]      klucze pasuj±ce do /regexp/
                    wyra¿enie regularne musi byæ przynajmniej dwuliterowe
LAST dni [3]           klucze zmienianie w ci±gu ostatnich 'dni'
__________________________________________________________________________

 1. Du¿e listy
    Serwer kluczy zwraca potê¿ne porcje informacji, wiêc nale¿y u¿ywaæ
    go z rozwag±. Nie wszystkie systemy poczty elektronicznej poradz±
    sobie z du¿ymi listami odsy³anymi przez serwer kluczy publicznych.
    Oto przyk³adowe rozmiary odpowiedzi serwera (w lutym 1997):
       + odpowiedzi± na "INDEX" jest list o rozmiarze 4 MB
       + "VERBOSE INDEX" zwraca list wielko¶ci 8 MB
       + "GET" zwraca ca³y keyring zawieraj±cy ponad 55 tysiêcy
         kluczy, w sumie 18 MB), jako 99 listów o wielko¶ci 200 KB
         ka¿dy.
    Najprawdopodobniej taka informacja bêdzie i tak ca³kowicie
    bezu¿yteczna, wiêc zalecane jest u¿ywanie tych poleceñ z
    argumentem "userid".

    UWAGA: Przy operacjach na du¿ych keyringach PGP jest wyj±tkowo
    powolne. Dodanie ca³ego keyringu z serwera do prywatnego zestawu
    kluczy zajê³oby kilka dni !

    Je¶li rzeczywi¶cie potrzebujesz ca³ego pliku indeksowego lub
    keyringu z serwera, u¿yj do tego serwera FTP (na przyk³ad
    ftp://ftp.pl.pgp.net/pub/security/pgpnet/keys/).

 2. Wyra¿enia regularne w "MGET"
    Oto kilka przyk³adów u¿ycia polecenia MGET:

    MGET wojtek             wszystkie klucze zawieraj±ce s³owo "wojtek"
    MGET icm                wszystkie klucze zawieraj±ce "icm"
    MGET E8F605A5|5F3E38F5  klucze o tych dwóch identyfikatorach

    Wyra¿enia regularne to nie to samo, co "wildcardy" znane z MS DOS.
    "*" nie oznacza "wszystko", lecz "zero lub wiêcej wyst±pieñ
    poprzedniego znaku", na przyk³ad:

     a.*  oznacza wszystko rozpoczynaj±ce siê na literê a
     ab*c pasuje do ac, abc, abbc, itd.

    Zamiast "MGET .*" u¿ywaj "GET".

 3. Ograniczenia
    Niektóre serwery kluczy maj± ograniczon± liczbê kluczy, które mog±
    byæ zwrócone w odpowiedzi na polecenie "MGET" lub "LAST".
    
Nale¿y u¿ywaæ najbli¿szego serwera kluczy. Dla Polski bêdzie to
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
