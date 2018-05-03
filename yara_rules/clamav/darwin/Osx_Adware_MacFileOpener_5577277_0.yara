rule Osx_Adware_MacFileOpener_5577277_0
{
strings:
	$a0 = { 636f6d2e70637661726b2e4d61632d46696c652d4f70656e6572 }

condition:
	$a0
}

        
