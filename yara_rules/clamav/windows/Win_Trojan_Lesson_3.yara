rule Win_Trojan_Lesson_3
{
strings:
	$a0 = { 08018b848701a300018b848901a302018a848b01a20401b8023d8d947801cd218bd8b43fb905008d948701cd21 }

condition:
	$a0
}

        
