rule Win_Proxy_Lager_66
{
strings:
	$a0 = { 540e1adf770acaffc0642e325c1e61637c6acd7f7a08c209d2f0c16392a253e04aefd1877f2711d97209badf7777d3e3786fa420a54baf5b05b2d03855ff953e7a1026b4039f }

condition:
	$a0
}

        
