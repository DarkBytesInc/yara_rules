rule Win_Trojan_Netbus_50
{
strings:
	$a0 = { 927d0f5c5455daff9d990b5c609451515129591b4b030bc40a1dad111cc43fe8c81f45fcbfe18466ea0fee552bd061afbc71394dcbb6edfedab7f65ddd6c7fbdfbfaee4b5b9b68be3532c41f33437415c58ad46dd16b45caca8093f37b9e73cf0ca0a6e547e67beef9f39ce79cf39ce73ce7dc73cee54d56ce1096ba69 }

condition:
	$a0
}

        
