rule Win_Spyware_Banker_3476
{
strings:
	$a0 = { c684c4661c5685712b61050d2ba034746de7254d599132da226b33392ebc8e7c7434a710b221d9e39a71d1dd34cdc1c7b357ae9c0937f4e94864411e735ed5a7b0f937097c102ea10a331dd0092f45b2 }

condition:
	$a0
}

        