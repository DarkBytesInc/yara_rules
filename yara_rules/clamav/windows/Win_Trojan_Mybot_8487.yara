rule Win_Trojan_Mybot_8487
{
strings:
	$a0 = { 1efac1a46f411f1703297e6d13529e62334382bc5e48d60907930aa5e29ed7a8c7fbfe8b65a0e2954cdea900a165baf78a6f2f8852db994d55e6724297f05c48ea5fd9128ff16e4972b2ea9eead3460520b1fee3f6 }

condition:
	$a0
}

        
