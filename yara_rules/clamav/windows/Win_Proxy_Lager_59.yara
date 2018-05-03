rule Win_Proxy_Lager_59
{
strings:
	$a0 = { 48f88385a48be58096a0ccd46e4efc115d3cb7e534ab2165863e8bc07e97cf774742310450ae8484897a5cfffe55335f49da7adcd7d67338f1c486db5546b47e8badb947e168 }

condition:
	$a0
}

        
