rule Win_Trojan_Renos_20
{
strings:
	$a0 = { ffff83c17701d101ca81ea001500004129c901ca4a039550feffff238d68ffffff09d181c1001d0000098d18fdffff3155b8398d44feffff731eba1100000009ca09ca318dacfeffff298d48fdffff098d24fdffff2355d8298d28ffffff318df0fdffff }

condition:
	$a0
}

        
