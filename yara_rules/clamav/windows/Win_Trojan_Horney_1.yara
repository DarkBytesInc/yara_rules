rule Win_Trojan_Horney_1
{
strings:
	$a0 = { 4b005589e531c09acd024b00e88cfdb801009a16014b005d31c09a16014b000000000000000000000000000055 }

condition:
	$a0
}

        
