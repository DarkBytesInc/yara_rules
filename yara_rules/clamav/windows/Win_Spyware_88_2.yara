rule Win_Spyware_88_2
{
strings:
	$a0 = { 94a9e33176e180a1af0d74cdf940f1039ac05f9ba10019a2083c7d80e97dbd8b4225da16ea610a4012008d3fe5257d27403656d5c2dbd15362cbd4266682da897f756093bbc8fafe5ed0fa7444c3ceaf03169a4819a1af96aeb777b91bc674f785e1e94315db52c4e2b9a1ba15646c5c629043699cf19a1041d3a9be0c29dfe8 }

condition:
	$a0
}

        