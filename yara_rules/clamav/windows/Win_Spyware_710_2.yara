rule Win_Spyware_710_2
{
strings:
	$a0 = { 432c4a20e07704883f466506554b220e6a48ea5608cca17fcdaa8cc2b770951abf49ebaaaee1a124ae528a993cdd2856028c1e39ffbaefb6183369f05ecbc98bdba7f46579483b7dc0ed8f0f2fdbf02df3721e6101fe3cfca1e837ba669e6798f5603f0a }

condition:
	$a0
}

        
