rule Win_Trojan_Agent_34705
{
strings:
	$a0 = { 555756533e0f2a0424dcd06a0090682e646c6c9068656c333290686b65726e9054ff155090410083 }

condition:
	$a0
}

        
