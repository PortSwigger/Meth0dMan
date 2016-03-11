#Meth0dMan

Meth0dMan is a [Burp Suite](http://www.portswigger.net/burp/) extension to aide in testing [HTTP Methods](https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)). It generates a custom intruder payload based on the hosts site-map, allowing quick identification of several HTTP Method issues. 

##Features

* Custom intruder payloads based on current site-map
* Automatic parameter highlighting within the intruder
* Works for both Free and Professional version of Burp Suite
* Find directory listings, [Cross-Site Tracing (XST)](https://www.owasp.org/index.php/Cross_Site_Tracing) and other issues without using the scanner

##How To Use It

1. From the _Extender_ tab in Burp Suite, add [Meth0dMan.jar](https://github.com/AOCorsaire/Meth0dMan/releases) 
2. Spider or discover content on site to build the site-map
3. Send a request Meth0dMan (creates a new intruder attack)
![Send to Meth0dMan](http://i.imgur.com/zdpQnwA.png)
4. Adjust the attack Type to 'Cluster Bomb'
5. Set the first payload to HTTP Verbs
6. Set the second payload to "Extension-generated"
7. Select generator, choose "Meth0dMan Payloads" from the drop down list
8. Ensure you have URL encoding **off** and start fuzzing!  
![Extension Generated Payloads](http://i.imgur.com/wchdCKV.png)
