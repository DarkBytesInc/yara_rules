rule Win_Worm_SomeFool_41
{
strings:
	$a0 = { 50ffd30fb7c003c78dbde8feffff0345f88365f400897de889 }
	$a1 = { 4238d974d184c97451f7c20300000075ed0bd8578bc3c1e310560bd88b0abffffefe7e8bc18bf733cb03f003f983f1ff }
	$a2 = { 2b4df08bf1894df8c1fe044e83fe3f7e036a3f5e3bf70f840d0100008b4a043b4a08756183ff207d2bbb000000808bcf }
	$a3 = { 894c32fc8b75f48b0e85c98d7901893e751a3b1d }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
