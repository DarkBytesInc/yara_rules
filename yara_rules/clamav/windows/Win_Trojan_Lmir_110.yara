rule Win_Trojan_Lmir_110
{
strings:
	$a0 = { e0400068a4e04000e82a61ffff85c075168d45fc506a006a426894df40006a006a00e8a060ffff8bc35b595dc20c004c69755f6d617a69000000004564697400000000b801000000c38bc033c0c39033c0c390558bec33c05568e1e0400064ff30648920ff05fc06410033c05a595964891068e8e04000c3e95649ffffebf85dc38bc0832dfc06410001c3558bec33c0556813e14000 }

condition:
	$a0
}

        