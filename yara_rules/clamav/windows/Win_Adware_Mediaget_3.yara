rule Win_Adware_Mediaget_3
{
strings:
	$a0 = { 4d5a9000 }
	$a1 = { 6e6c6f6164536572766572733e646f776e6c6f61642e6d656469612d6765742e72752c646f776e6c6f6164322e6d656469612d }

condition:
	$a0 and $a1
}

        
