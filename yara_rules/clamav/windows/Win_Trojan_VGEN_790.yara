rule Win_Trojan_VGEN_790
{
strings:
	$a0 = { 05100005000050b80000501e060e1ffa33c0068ec026c70690008701268c1e920007fbbaf401b41acd21b419cd21 }

condition:
	$a0
}

        
