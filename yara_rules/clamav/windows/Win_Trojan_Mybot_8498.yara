rule Win_Trojan_Mybot_8498
{
strings:
	$a0 = { 21b7d2123d09d1f55a707af056b878a0723dfac810c6358f29bc9b70b5219cbc7b7fb555ede5310cb63e6043c6379a61cdcb3f6f75ba558898fd48839e3e1ccf014ffe9f6ca2edd3c74d334f5c798e12dba0bdd4f8 }

condition:
	$a0
}

        
