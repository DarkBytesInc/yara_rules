rule Win_Trojan_Kiss_3
{
strings:
	$a0 = { e800005eb49f53511e06cd2183ee0380fc217502eb6b33c050b42acd2180fa15750e80fe087509b409bae50303d6cd218cd8488ec01fa184008b0e86002e8984 }

condition:
	$a0
}

        
