rule Win_Adware_Lookme_31
{
strings:
	$a0 = { 0d1ed02f9ebdd706c4b76cf14a970cfecf3b1c4b7a8df5f22fac60b39e1837619dc7f7b20c9446c3a66f7f870aa8f4d7cc8fb154376639c525baab99985128ee557b5ff31d79be6737cae4f7be64cf3bed4abb574e49832c366f408b4d611b0b4f58309b60632bbbe3487a7f0aff }

condition:
	$a0
}

        
