rule Win_Adware_Webhancer_21
{
strings:
	$a0 = { 52656753657456616c756545784100 }
	$a1 = { 534f4654574152455c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c55524c5c44656661756c7450726566697800 }
	$a2 = { 534f4654574152455c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c55524c5c507265666978657300 }
	$a3 = { 616464206164766572746973656d656e74 }
	$a4 = { 5245474953544552 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        