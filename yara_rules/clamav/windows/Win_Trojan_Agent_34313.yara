rule Win_Trojan_Agent_34313
{
strings:
	$a0 = { 8bf033db33c08945f88b462033d25250a1a48b4000990304241354240483c40852508bc3c1e00233d20304241354240483c4088b0033d25250a1a48b40009903 }

condition:
	$a0
}

        