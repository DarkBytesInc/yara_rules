rule Win_Worm_Koobface_26
{
strings:
	$a0 = { 23424c41434b4c4142454c }
	$a1 = { 26636b3d256426635f66623d256426635f6d733d256426635f68693d256426635f62653d256426635f66723d256426635f79623d256426635f74673d256426635f }

condition:
	$a0 and $a1
}

        