rule Win_Trojan_VGEN_664
{
strings:
	$a0 = { 7b045f0d499783c70e31054747ab6da2d6df98399736a71d8c2983669535a61d8c1f92319c84b7497eaf94497d429e }

condition:
	$a0
}

        
