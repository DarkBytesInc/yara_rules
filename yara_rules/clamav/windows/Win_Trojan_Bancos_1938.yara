rule Win_Trojan_Bancos_1938
{
strings:
	$a0 = { ffafd3e4b392d6587ee6f4bfc632fb55fe6ffed7a30b65b5de382a40209df8bb3ec9f81b02a6dd711c17473f1e20881692da21a085f1b95f91b3ab307e6a6b72689d0fd430f1ba64af6efe381e76ed669561ba0028bfac2cacf9 }

condition:
	$a0
}

        
