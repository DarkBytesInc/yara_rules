rule Win_Trojan_IRCBot_608
{
strings:
	$a0 = { 668ef1adf4b54be38855c07ecef2a03bb3cfb291e2ec6dce37313e9ce954eded4faa04932c5081f7b8066ce39f2326b6dbbcab45328dd8598e5b148a7bd2991d90850c4a152b7f478c1ced96942a38c2105eaa8140d929f3d0279a536f07bcd1460563689d33bf3dd4e37b7a1de86ccdcee8eddf05097a1c33d3f270d25a63284133c718cd6e33dfbaa7adde9fbe }

condition:
	$a0
}

        