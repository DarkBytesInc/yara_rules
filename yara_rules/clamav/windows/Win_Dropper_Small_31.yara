rule Win_Dropper_Small_31
{
strings:
	$a0 = { 71f019597418573ea30fb3d185824e043cd48cb16f6c1bcff61e8964756f687447b62b63b3dc554a8d0713dd78273e6cc8dc5d40686ccd22f6c946d120306a166db96c4d6d3c }

condition:
	$a0
}

        
