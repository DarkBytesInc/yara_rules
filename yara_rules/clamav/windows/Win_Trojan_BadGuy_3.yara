rule Win_Trojan_BadGuy_3
{
strings:
	$a0 = { 0190b90b1190b44ecd2190730390eb27ba9e0090b8023d90cd2190730390eb178bd890e83c00ba800090b44f90cd2190730390eb02ebd9b42acd213c0174 }

condition:
	$a0
}

        
