rule Win_Trojan_Agent_35223
{
strings:
	$a0 = { a7aef7e91a332f8e2858f3960abe48ba8093e2275d5ea810ebf6704fa044deae8d651567accd429376bedb9ed90d2bd3b77d0443c99b6f1d71ab6241f1d0cc46b64ad5ec73b20433cfcd0879d9442415466145e87145ffedae67fe26 }

condition:
	$a0
}

        
