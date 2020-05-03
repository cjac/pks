<?php
  if ($server) {
    $pgpserver=$server;
  } else {
    $pgpserver="dmzs.com";
  }
  $port="11371";
  $pgplookup="/pks/lookup";
  $pgpadd="/pks/add";
  $webserver="http://www.dmzs.com/";
  $url="~dmz/projects/pks-commands.php";

  echo "<?xml version=\"1.0\"?>"
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
<?php
if (!$docmd) {
?>
    <title>OpenPGP Public Key Server Commands</title>
  </head>
  <body>
  <h1>OpenPGP Public Key Server Commands</h1>
  <h2>
  <a href="#extract">Extract a Key from the Server</a>
  </h2>
  <h2>
  <a href="#submit">Submit a Key to the Server</a>
  </h2>
  <hr />
  <h2>
  <a id="extract" name="extract">Extracting a Key</a>
  </h2>
  <p>Here is how to extract a key:</p>
  <ol>
    <li>
      <p>Select either the &quot;Index&quot; or &quot;Verbose Index&quot; check box. The &quot;Verbose Index&quot; option also displays all signatures on displayed keys.</p>
    </li>
    <li>
      <p>Type ID you want to search for in the &quot;Search String&quot; box.</p>
    </li>
    <li>
      <p>Press the &quot;Do the search!&quot; key.</p>
    </li>
    <li>
      <p>The server will return a (verbose) list of keys on the server matching the given ID. (The ID can be any valid argument to a pgp -kv(v) command. If you want to look up a key by its hexadecimal KeyID, remember to prefix the ID with &quot;0x&quot; .)</p>
    </li>
    <li>
      <p>The returned index will have hypertext links for every KeyID, and every bracket-delimited identifier (i.e. &lt; 
      <a href="<?php echo $webserver . $url ?>?docmd=lookup&amp;op=get&amp;exact=on&amp;search=dmz@dmzs.com">dmz@dmzs.com</a>
       gt;). Clicking on the hypertext link will display an ASCII-armored version of the listed public key.</p>
    </li>
  </ol>
  <hr />
  <form action="<?php echo $webserver . $url ?>" method="get">
    <input type="hidden" name="docmd" value="lookup">
    <p>Server:
		<select name="server">
      <option value="dmzs.com" selected="selected">DMZ Services</option>
      <option value="keys.pgp.com">NAI</option>
      <option value="pgp5.ai.mit.edu">BAL MIT</option>
      <option value="pgp.cc.gatech.edu">GA Tech</option>
      <option value="pgp.es.net">ESnet</option>
    </select>
		</p>
    <p>Index: 
    <input type="radio" name="op" value="index" checked="checked" />
     Verbose Index: 
    <input type="radio" name="op" value="vindex" />
    </p>
    <p>Search String: 
    <input name="search" size="40" />
    </p>
    <p>
    <input type="checkbox" name="fingerprint" />
     Show OpenPGP &quot;fingerprints&quot; for keys</p>
    <p>
    <input type="checkbox" name="exact" />
     Only return exact matches</p>
    <p>
    <input type="reset" value="Reset" />
     
    <input type="submit" value="Do the search!" />
    </p>
  </form>
  <hr />
  <strong>Extract caveats:</strong>
   
  <ul>
    <li>
      <p>Currently, hypertext links are only generated for the KeyID and for text found between matching brackets. (It&#39;s a common convention to put your e-mail address inside brackets somewhere in the key ID string.)</p>
    </li>
    <li>
      <p>The search engine is not the same as that used by the gpg(1) or pgp(1) programs. It will return information for all keys which contain all the words in the search string. A &quot;word&quot; in this context is a string of consecutive alphabetic characters. For example, in the string &quot;user@example.com&quot;, the words are &quot;user&quot;, &quot;example&quot;, and &quot;com&quot;.</p>
      <p>This means that some keys you might not expect will be returned. If there was a key in the database for &quot;User &lt;example@foo.com&gt;&quot;, this would be returned for by the above query. If you don&#39;t want to see all these extra matches, you can select &quot;Only return exact matches&quot;, and only keys containing the specified search string will be returned.</p>
      <p>This algorithm does 
      <em>not</em>
       match partial words in any case. So, if you are used to specifying only part of a long name, this will no longer work.</p>
    </li>
  </ul>
  <hr />
  <h2>
  <a id="submit" name="submit">Submitting a new key to the server</a>
  </h2>
  <p>Here is how to add a key to the server&#39;s keyring:</p>
  <ol>
    <li>
      <p>Cut-and-paste an ASCII-armored version of your public key into the text box.</p>
    </li>
    <li>
      <p>Press &quot;Submit&quot;.</p>
    </li>
  </ol>
  <p>That is it! The keyserver will process your request immediately. If you like, you can check that your key exists using the 
  <a href="#extract">extract</a>
   procedure above.</p>
  <hr />
<form action="<?echo $webserver . $url ?>" method="post">
  <input type="hidden" name="docmd" value="add">
  <p>Server:
	  <select name="server">
      <option value="dmzs.com" selected="selected">DMZ Services</option>
      <option value="keys.pgp.com">NAI</option>
      <option value="pgp5.ai.mit.edu">BAL MIT</option>
      <option value="pgp.cc.gatech.edu">GA Tech</option>
      <option value="pgp.es.net">ESnet</option>
      </select>
		</p>
    <p>Enter ASCII-armored PGP key here:</p>
    <p>
    <textarea name="keytext" rows="20" cols="66"></textarea>
    </p>
    <p>
    <input type="reset" value="Reset" />
     
    <input type="submit" value="Submit this key to the keyserver!" />
    </p>
  </form>
  <hr />
  <address>
    <p>Marc Horowitz 
    <a href="mailto:marc@mit.edu">&lt;marc@mit.edu&gt;</a>
    </p>
  </address>
<?php
} else {
?>
    <title>OpenPGP Public Key Server <?php if ($docmd=="lookup") {echo "Lookup";} else {echo "Add";}?></title>
	</head>
	<body>
  <h1>OpenPGP Public Key Server <?php if ($docmd=="lookup") {echo "Lookup";} else {echo "Add";}?></h1>
<?php 
  if (!$fingerprint) {
    $fingerprint = "off";
  }
  if (!$exact) {
    $exact = "off";
  }
  if ($docmd == "lookup") { 
    $servercommand = "GET $pgplookup?op=$op&exact=$exact&fingerprint=$fingerprint&search=$search HTTP/1.0\n\n";
    $regexstr = "/pks\/lookup\?/";
    $replacestr = $url . "?docmd=lookup&";
    if ($server) {
      $replacestr .= "server=" . $server . "&";
	  }
  } else if ($docmd == "add") {
    $newkey="keytext=".rawurlencode($keytext);
    $keylen=strlen($newkey);
    $servercommand = "";
    $servercommand .= "POST $pgpadd HTTP/1.0 \r\n";
    $servercommand .= "Referer: \r\n";
    $servercommand .= "User-Agent: php-pkscommands/0.2 \r\n";
    $servercommand .= "Host: " . $webserver . "\r\n";
    $servercommand .= "Content-type: application/x-www-form-urlencoded\r\n";
    $servercommand .= "Content-length: " . $keylen . "\r\n\r\n";
    $servercommand .= $newkey;
    $regexstr = "/pks\/add\?/";
    $replacestr = $url . "?docmd=add&";
  }
  $fp = fsockopen($pgpserver, $port, &$errno, &$errstr, 30);
  if (!$fp) {
    echo "Error with OpenPGP Key Server. " . $errstr . "(" . $errno . ")<br>\n";
  } else {
    fputs($fp, $servercommand);
    while (!feof($fp)) {
      $line = fgets($fp, 80);
      if (!strstr($line, "HTTP") && !strstr($line, "Server: pks_www") && !strstr($line, "Content-type: text/html")) {
        echo preg_replace($regexstr,$replacestr,$line);
      }
    }
  }
  fclose($fp);
  echo "<hr /><a href=\"" . $webserver . $url . "\">Back</a>";

  endif
?>
	<!-- $Id: pks-commands.php,v 1.2 2003/02/07 01:11:35 rlaager Exp $ -->
  </body>
</html>
