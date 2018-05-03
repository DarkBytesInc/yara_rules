rule Unix_Tool_13673_1
{
strings:
	$a0 = { eb255b31c031c931d289430bb00acd80eb085b895308b00bcd80e8f3ffffff706f7765726f6666e8d6ffffff2f6574632f736861646f77 }

condition:
	$a0
}

        
