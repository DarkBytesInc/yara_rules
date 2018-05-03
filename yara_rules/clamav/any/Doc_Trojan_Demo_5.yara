rule Doc_Trojan_Demo_5
{
strings:
	$a0 = { 4966204e542e4c696e657328312c203129203c3e2022273c44656d6f3e22205468656e }

condition:
	$a0
}

        
