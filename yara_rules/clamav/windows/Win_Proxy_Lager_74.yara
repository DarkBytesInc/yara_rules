rule Win_Proxy_Lager_74
{
strings:
	$a0 = { 676f0215ba4b096e1ab2760d4aff330b651080811c9fecf80a8a773a3a01855bffc3a10a72c7a703fc8339ef8fe53cdda4cc68254afcad1638b7597faf21d9cd3a8b7c3593cf }

condition:
	$a0
}

        
