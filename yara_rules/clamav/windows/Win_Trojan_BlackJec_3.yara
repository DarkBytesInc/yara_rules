rule Win_Trojan_BlackJec_3
{
strings:
	$a0 = { 90909090b9800090be800090bf7fff90f3a4b87a028bc82d0001a3fa00030e4802890ef80003c8890ef600908bc8be00018b3ef800f3a4f990ba410290b4 }

condition:
	$a0
}

        
