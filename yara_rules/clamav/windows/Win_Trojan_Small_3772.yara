rule Win_Trojan_Small_3772
{
strings:
	$a0 = { cf8bde79f70da7389fb55c6bdfdde19017deb4781c19ac2e600af428c9b7b52bf735a7389f885c099cddb4fb5bc54b0cbbc54b6d97cdf478c083e923c61ee22ff7dda4789fb7bc878ae5a4389f8d4b6da3cdf478142dde78f5fee2129f22a12c8f9db4fd5fa986f3a2eda4389f8b4baf1a1dc0 }

condition:
	$a0
}

        
