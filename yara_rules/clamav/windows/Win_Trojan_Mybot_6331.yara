rule Win_Trojan_Mybot_6331
{
strings:
	$a0 = { 7687e09497eea18f82eb15cbafbcda4a0e9d5e5c5aa414251207a9ba4a761e653ed7fcab62fc60fc29ebbb0664d0389fb68fff5f5e985666baf486c1b14cd46c6a7c596594a14b68fca81fa43c04e315a8dbf36d1d3421368c837394088d7b0f74745676e0728fc13e68949ce6c41dbe163b470b30644985c2d1bb407ee37eebce18fbd288c764a361c4f6a48a3e92e0340fcfd57e56 }

condition:
	$a0
}

        