rule Win_Trojan_Spambot_200
{
strings:
	$a0 = { 6eea5bbcb717a7cde0b68f4db12f49480e8052f525c2e8fffbffcbd54cc0026e91825fe593f1a32f6e3c6e3808f54bedf63bffffffff8f258df32d8d0672d6b9dceab379996571a22e0854473558127469c80bfcc1fdd3ffff126602071c16e407d45a02da247c482b1660a77cdd }

condition:
	$a0
}

        
