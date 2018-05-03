rule Html_Trojan_Blackhole_64
{
strings:
	$a0 = { 7472797b66617762652b2b7d63617463682861666e77656e657729 }

condition:
	$a0
}

        
