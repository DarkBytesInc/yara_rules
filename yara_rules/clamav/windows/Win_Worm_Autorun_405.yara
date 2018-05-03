rule Win_Worm_Autorun_405
{
strings:
	$a0 = { 6f6e5c52756e[0-10]52656379636c65642e6578 }
	$a1 = { 756c2e646c6c }
	$a2 = { 66697273747365747570 }
	$a3 = { 5c6175746f72756e2e696e66 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
