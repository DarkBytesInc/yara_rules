rule Win_Trojan_Legmir_1
{
strings:
	$a0 = { 51bfddd2ec4929fc8544b424016768ffd88ffdc20f1f61d58bf08b841150eb1b8b8c09d666c3da51e01c2c23b2baed9bfb53feffff951a56ffd38b5914af1cf85df7f7355c935285c9d5215e5d5b5f81c40b2f9c70a2ae90df44568b0a4cff5c }

condition:
	$a0
}

        
