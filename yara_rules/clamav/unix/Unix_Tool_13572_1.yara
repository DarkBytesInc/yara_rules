rule Unix_Tool_13572_1
{
strings:
	$a0 = { eb115e31c031c931d2b00a89f3cd80b001cd80e8eaffffff2f6574632f706173737764 }

condition:
	$a0
}

        
