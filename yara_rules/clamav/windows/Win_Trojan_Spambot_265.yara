rule Win_Trojan_Spambot_265
{
strings:
	$a0 = { dc79d291224935dd3b5775bfe037d8696522746e8d9d90f2ffffffffd6ecf1158faed3fc34fff53406f9f5d8ef5f6e42f6437155d30f53592f21370efffff0ff82fb1a8e8e19d6fd47cea8dba1dae1d6ae79382c93666d82e934ffff0ff0e995392d7f9d69d69d8d14cdfe23f66c }

condition:
	$a0
}

        
