rule Win_Trojan_Agent_32824
{
strings:
	$a0 = { 414f591a3b088a78a2ec6de43080939f926d9133195b827120618850aabb2b4104ddc7ec3a6bd13ded2445dcb35041aaa687258ab0b8c39bf1f88cd6697e451f4d }

condition:
	$a0
}

        
