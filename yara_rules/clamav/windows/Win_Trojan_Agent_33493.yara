rule Win_Trojan_Agent_33493
{
strings:
	$a0 = { 50401e39dac09f75fa86882c3989bcef96a5009c88f59fee43d0fd19482e9ab6db3029c4cd89eac60ea481ac865e6fa86af0934e8f9644d30a9e54c060c4b048d98ce7f939de0ff603d179f5e6a98ee688c707e83eec }

condition:
	$a0
}

        
