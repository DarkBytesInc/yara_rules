rule Win_Dropper_Agent_33576
{
strings:
	$a0 = { 8ab9556a625d0da954ab3bb95f5bb2482f31e15c153cee19168f13465930cd9a6f716d7b6cc470f6526f357b2c79b46b3657f938e89b50fe62d5ef4bb5e4cf9b79755afc3659c72f2d7a2f4cfb87ccbb34e1bb47 }

condition:
	$a0
}

        
