rule Win_Spyware_Banker_4525
{
strings:
	$a0 = { 5bd6e96ef4b1d26b956edcf3da4146e34ff912256c40d38c204f6ddef8c7ab1293c1f3ea43bbbc8640b4e3a094cd0116c7bc59bc473c7ca7e074fd0126a94904b59d45ad0d3ee7657e96ee5f1e0c3f069c65b5aad89b206b76ea81ee739a02877f456201 }

condition:
	$a0
}

        
