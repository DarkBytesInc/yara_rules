rule Win_Worm_Koobface_30
{
strings:
	$a0 = { 633a5c333433346664672e626174 }
	$a1 = { 424c41434b4c4142454c }
	$a2 = { 633a5c6434352e626174 }

condition:
	$a0 and $a1 and $a2
}

        
