rule Unix_Tool_13473_1
{
strings:
	$a0 = { 31c0505050347ecd8058682f2f7368682f62696e89e350545350343bcd80 }

condition:
	$a0
}

        
