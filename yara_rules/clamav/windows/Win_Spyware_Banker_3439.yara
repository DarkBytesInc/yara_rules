rule Win_Spyware_Banker_3439
{
strings:
	$a0 = { 3d53641051ce0fd9efaf9c394db5b54ef34eca86bd49bfbf236940f22de152b949a7b51eea0300e788c505c394dfd141d65a9d908d8ac30e8d7b4a906264a0cb522a4ba42d3bd37697d4ab25bc534ff5b176856cfb2c85b8f9b8a6f95b569c }

condition:
	$a0
}

        
