rule Win_Trojan_Bancos_1180
{
strings:
	$a0 = { 7ad5148f8a07a2cb66304a252364a032d1c7d3b42d470e8787089f9d1aafc66badae9ba92f58f8fc9e2e96a9c756c9c3facbe9d5485cee1fe00cae2047accdb506597f13bb6e8f17b376af3af907c8f8090f7f60e6a1d1671975 }

condition:
	$a0
}

        
