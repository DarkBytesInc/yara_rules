rule Win_Worm_Sober_30
{
strings:
	$a0 = { 623a446f65726b15197d2b60aa896b7310466f726d6df146b07626ac280032fe95bddbc9cfa2035a0044950121b96eab6f6fac536f623b47000b021c }

condition:
	$a0
}

        
