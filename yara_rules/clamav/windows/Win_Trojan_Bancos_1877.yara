rule Win_Trojan_Bancos_1877
{
strings:
	$a0 = { b5f08458721697e4dc68101ff2a5c1922477c49033e01c675def9044363c5bfc692ea94c9d84e9b9daa4c2471082e6c758370d7afaf3efca069689fd7b235c15bdce6485f24a }

condition:
	$a0
}

        
