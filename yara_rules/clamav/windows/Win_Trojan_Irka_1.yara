rule Win_Trojan_Irka_1
{
strings:
	$a0 = { 5a4152440874656d702e6565650120052a2e657865052a2e636f6d9a0000c9005589e5b80202 }

condition:
	$a0
}

        
