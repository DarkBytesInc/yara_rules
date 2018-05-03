rule Win_Proxy_Lager_47
{
strings:
	$a0 = { f81eaee6d86a02fade080d8c76f00ee636a29c65eeef1e02db27de5cd609755ad3771c66dc6f6ba5014b60dea1b21fbdf1ff5abbde10e931a79f8548b18a1e8a8101eceb44c3 }

condition:
	$a0
}

        
