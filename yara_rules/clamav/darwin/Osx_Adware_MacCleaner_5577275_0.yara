rule Osx_Adware_MacCleaner_5577275_0
{
strings:
	$a0 = { 636f6d2e70637661726b2e4d61632d4164776172652d436c65616e6572 }

condition:
	$a0
}

        
