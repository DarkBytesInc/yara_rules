rule Win_Trojan_Crypted_35
{
strings:
	$a0 = { 223a666f7220693d3120746f206c656e2863293a743d63687228617363286d696428632c692c3129292b31293a6b3d6b2b743a6e6578743a65786563757465206b }

condition:
	$a0
}

        