rule Win_Trojan_Lesson_2
{
strings:
	$a0 = { ee06018b847601a300018a847801a20201b8023d8d946701cd218bd8b43fb903008d947601cd21b8024233c933d2 }

condition:
	$a0
}

        
