rule Win_Trojan_NetTaxi_2
{
strings:
	$a0 = { d002c00347041206001a0100620023ff24003b00ff012100000003060054696d657236000b020003d007000007000000000878000000ff032100000004060054696d657235000b02000301000000070000000008e0010000ff02032500000005080050696374757265320000 }

condition:
	$a0
}

        