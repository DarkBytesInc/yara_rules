rule Win_Trojan_SdBot_4144
{
strings:
	$a0 = { 9c5b3e1deebf4453c637897d8b0b552998c5fccfebf59708f4a7aec187bb159bddbf11ab545ea78553ce779d8ae343dca8e36ffc3fdea84f4e3de74615ebc4a9a98a714397e446afd30be8b41e2b5599fe3f5ca73313cfb718aa67d2c83bc1215e88af8b1235fd48a15cd46bbcfe6eb40f6ab634e767eb789a30e7eb6f905e3e }

condition:
	$a0
}

        
