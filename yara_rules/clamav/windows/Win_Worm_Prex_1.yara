rule Win_Worm_Prex_1
{
strings:
	$a0 = { a7eb7542750000000000030003000000280000800e00000008060080100000007806008000000000a7eb75427500000000000300317500005000008032750000a801008033750000b804008000000000a7eb754275 }

condition:
	$a0
}

        