rule Win_Spyware_Banker_5665
{
strings:
	$a0 = { 7421bc24ae35ee766fed5af6f2b0f29d1868aff238ebae8dfd8eee9f99016891ed9b0397ff2c00e119a5acd974dc3b8ae953f4f7382522d41fa013a2c3fe1662de851eea29825454aaaf43145970f9c83fa919baffaabfd97b2ebde7af779d5f207acddffdaadce72e3763cd1fe8581323a8d94f4551d9b7007b6544251b03e7 }

condition:
	$a0
}

        
