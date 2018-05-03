rule Win_Worm_Autorun_387
{
strings:
	$a0 = { 5c4e65744d656574696e672e657865 }
	$a1 = { 73746f726d2e657865 }
	$a2 = { 5c646f776e6c6973742e747874 }
	$a3 = { 53746172747570 }
	$a4 = { 5b6175746f72756e5d }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
