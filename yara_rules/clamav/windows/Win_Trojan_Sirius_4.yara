rule Win_Trojan_Sirius_4
{
strings:
	$a0 = { 1801ba0000b90000311490909090464690e2f590e800005d81ed1b01b8fefecd2181fe9419744733c08ed8c51e8400 }

condition:
	$a0
}

        
