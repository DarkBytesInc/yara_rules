rule Unix_Tool_13350_1
{
strings:
	$a0 = { 31d26a0f58526a776668646f682f736861682f65746389e36668b60159cd806a0158cd80 }

condition:
	$a0
}

        
