rule Win_Trojan_Hupigon_762
{
strings:
	$a0 = { b9488b4798be88c800174df15311268305eee63b16e55b023ad53f1fc3ecd0397398fd9b429cdc53e487a8fbef0b9e6bb3a63602f6df16b3f32605f5c7a6139f35e29c8291009ebc98bbcedd7451 }

condition:
	$a0
}

        
