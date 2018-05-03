rule Win_Worm_Autorun_260
{
strings:
	$a0 = { 40686f6d656472697665202620225c6c6f6722 }
	$a1 = { 2477696e70617468202620226175746f72756e2e696e6622 }

condition:
	$a0 and $a1
}

        
