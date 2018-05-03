rule Win_Ransomware_Locky_31469
{
strings:
	$a0 = { 558bec518d45??50ff15[4]50ff15[4]85c074158b4d??83f9027c0dff7488fcff15[4]59c9c333c0c9c3 }

condition:
	$a0
}

        
