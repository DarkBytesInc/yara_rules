rule Win_Trojan_Deltreey_1
{
strings:
	$a0 = { 4064656c74726565202f7920633a5c77696e726172203e6e756c[0-13]633a5c77696e7a6970203e6e756c }

condition:
	$a0
}

        
