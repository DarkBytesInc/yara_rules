rule Win_Downloader_Banload_363
{
strings:
	$a0 = { b2fd70ae5dd0418ab9fe24ab7f6d346649a4578db080ee45dabf2fae51968a31e680ae397a26aacde3789eb6fe62daf8373362c7c52cfbce4a1fbc09db6e170881156053b2c53f1981ef1b11eff73c71db7978f21ee289c7523f88ae56c5b1ef2789cc0666e6b8bab7 }

condition:
	$a0
}

        
