rule Win_Worm_Logex_1
{
strings:
	$a0 = { c745fc0b000000c785f4fdffff14284000c785ecfdffff080000008b4d0881c188000000518d95ecfdffff528d853cfeffff50ff1518114000 }

condition:
	$a0
}

        
