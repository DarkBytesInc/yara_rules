rule Win_Trojan_Bancos_1953
{
strings:
	$a0 = { fdb5bfabc34eafc9fb1ab6ab5632021110fd1d886ce69c7e4a0753a17aa8eba7dcb633c2b0923b24c3f70011efe443c0c8dbfa45e9d291054668560f272cd3bb6d80a5023be795777b407fb0d7d6673834f8b5a9da1ca960b3f8 }

condition:
	$a0
}

        
