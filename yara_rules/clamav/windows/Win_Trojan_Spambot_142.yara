rule Win_Trojan_Spambot_142
{
strings:
	$a0 = { 8cf174c6329dd34ab0f1a1f9f1418e13a76b86ffffffff688fe79a8b14b9216599a8dc1224b26f92999f1b012026b77de164107a7b6965faffffabaaad6f8e1d0cc4dd92237634c85ab23249f72d523f6e43faf5ffd79fc3f7bf5f814075f702873330ad830c07ffffff6fd4ef7b }

condition:
	$a0
}

        
