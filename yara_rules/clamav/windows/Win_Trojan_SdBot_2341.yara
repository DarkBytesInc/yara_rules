rule Win_Trojan_SdBot_2341
{
strings:
	$a0 = { 66760b091e28aa51058f88cefcfffe3e8681c7f5f8f7e084f1f3f2f1a6d8ecedeceb00e2002fe7716ab0dee1e04b9f1a9ec4e59bc1e227615aa0ced1d03b8f0a8eb4d5fd9bbf7c3ec4c3c212c0758bb9bcbb483fa9 }

condition:
	$a0
}

        
