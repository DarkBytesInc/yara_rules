rule Win_Trojan_Mybot_6113
{
strings:
	$a0 = { 2765de39a98874abf5c544cb4414f516a518232c12b6cd027ccf2d5cd1dc17d37fba02d4050aacd526b6db220ad2094ded1fede7251a1a0eb6dabf9881ccfa6bfff6f851e2be6535ff677755dc33111eeb6a0d616c1a0df5a5980cff0cdaef540fe0e7b9540a9acb58da74084af36e52f801eafc5367d2cb }

condition:
	$a0
}

        
