rule Win_Trojan_Ph33r_1
{
strings:
	$a0 = { 2900061f8cd80510000538498ed0bc49388cd805100005380050b838135033c033db33c933d233f633ffcbfcb8ff51 }

condition:
	$a0
}

        
