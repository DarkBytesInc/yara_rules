rule Doc_Trojan_Hopper_10
{
strings:
	$a0 = { 49662061642e4c696e657328312c203129203c3e2022273c212d2d424541542d2d3e22205468656e }

condition:
	$a0
}

        
