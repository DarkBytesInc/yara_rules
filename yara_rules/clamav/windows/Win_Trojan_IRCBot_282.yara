rule Win_Trojan_IRCBot_282
{
strings:
	$a0 = { 3f92fdef05a9c34bdd1400eacb513c89b8cc40f08e746235ab6bad31856b2dbd917b388946e9dc606d08611d0775d61a81523bdb95a28fbd98919f04817a74b81a5fe2dbf13a416e85993aa9b6b70897 }

condition:
	$a0
}

        
