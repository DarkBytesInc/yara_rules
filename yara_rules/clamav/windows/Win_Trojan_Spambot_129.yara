rule Win_Trojan_Spambot_129
{
strings:
	$a0 = { a4417c57a88b9fbcef4ccd70ffffffff1bda30e41b4e514ee16a641c129051aef6d7828d20a0fda63c3970c7718a5ff1ffffffffa27806f2adf71562c50547c4f01171940f1d0d79dd4ccba38840d8ec675729bcffd7ffff8eab4558f92bb744a3991d73db26ea840ceccbddbf65 }

condition:
	$a0
}

        
