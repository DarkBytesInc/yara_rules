rule Unix_Tool_13442_1
{
strings:
	$a0 = { eb315e31c088460a88460e88461a89761b8d7e0b897e1f8d7e0f897e23894627b00b89f38d4e1b8d5627cd8031c031db40cd80e8caffffff }

condition:
	$a0
}

        
