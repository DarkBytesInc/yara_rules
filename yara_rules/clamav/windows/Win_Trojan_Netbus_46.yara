rule Win_Trojan_Netbus_46
{
strings:
	$a0 = { 8a7d0d5c5455faff9d990b5c609051f12545251d4b050d44377430476110f16de44511df1391c8d41fdcabb6810e8d6c5c8eb3cbb6b6fffeff6a7fbad56eebfadb1fbbb985e6d6c8102f658664896249e66ee8a52265755472fecf73eeb9c368a6eb47eef7dcf3f29ce79cf39ce73ce7e59ee14d56ce10327bf3e68deb }

condition:
	$a0
}

        
