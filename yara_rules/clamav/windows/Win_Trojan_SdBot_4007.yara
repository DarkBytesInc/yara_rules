rule Win_Trojan_SdBot_4007
{
strings:
	$a0 = { 17a61fd126fd185de3bd86f15c9006cffe0b981c6e214ee45f196e4cafc1e66fc5bda216a562675c386cabb6dffde82fecae81050ca2c858824c39ccab3c15a9f02e39a4fd1ed22150bd65201214d898d3df94d0ed20add432a937dcb14f413808b678a6 }

condition:
	$a0
}

        
