rule Unix_Tool_13551_1
{
strings:
	$a0 = { 31c0506861646f77682f2f7368682f65746389e36668b60159b00fcd80b001cd80 }

condition:
	$a0
}

        
