rule Win_Worm_Bibrog_2
{
strings:
	$a0 = { 83c40cc745fc11000000c78550ffffffa4934300c78548ffffff080000008d45b0508d8d48ffffff518d9568ffffff52ff156c114000 }

condition:
	$a0
}

        
