rule Win_Trojan_SdBot_3645
{
strings:
	$a0 = { a6bea8c719b2f1d060465f669d6ccf63de7363f947dc040dc94a0a4330ce28b895fb95963ca35a41e39572b2733a9b75083ae9bf6ddf0d56579477931f1bc8a08c6fd58b341264aa4fe8dfbcb154 }

condition:
	$a0
}

        
