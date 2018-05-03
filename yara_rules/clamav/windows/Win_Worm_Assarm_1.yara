rule Win_Worm_Assarm_1
{
strings:
	$a0 = { c745a0c8734000c745a4d0734000c745a8e0734000c745acec734000c745b0f8734000c745b4047440006a30 }

condition:
	$a0
}

        
