rule Win_Dropper_Delf_610
{
strings:
	$a0 = { 8c65662f3829691e05d3f648e4ffc17f825b515761726e696e6721fe5468697320636ff17effff756c642062652061204d616c69676e75274170701363f6ffbd7f09696f6e2c205941200377616e7420746f }

condition:
	$a0
}

        