rule Win_Trojan_Spambot_216
{
strings:
	$a0 = { 24ffffffffb3ebf2015cba7b6c827d6587e2f3f101b1c028da5a5ea9ecdd93102ee119f497ffffffff6ba910c5a6e928633e8fa3d8fe5d3b2ff55478ad9fb3358f1f496581947e45cbffffffffc495832aa262f75c946adaa3f855c514b7190fd8f66e822367e840bee12d2bf5ff }

condition:
	$a0
}

        
