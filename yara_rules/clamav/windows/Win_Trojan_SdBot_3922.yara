rule Win_Trojan_SdBot_3922
{
strings:
	$a0 = { db7bf107c6d06c4338db829b337a15cc410c5d215d0e53f3995bd5934e78942e41e3b9ee8172b8496eb3f8dece4743b9f96e2e71bb9be8a2aa2eb26a4612ffffc83dacd1be5eef6a409abce89c3dd5b1d3e5e341bedb883289da0e4d }

condition:
	$a0
}

        
