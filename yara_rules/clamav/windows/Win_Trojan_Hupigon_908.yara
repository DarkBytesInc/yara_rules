rule Win_Trojan_Hupigon_908
{
strings:
	$a0 = { c05d0a35da6e0b37c039a5d7c2765b249ee125614509dfbcc63aa8870cbdadf5371b1e6c63ed7e2aaf97c97b7af4945ccdd46570d89a4a6165a50beebab6f9fcd1a39f5e0276a753de68656225ff22cc79f31277f72506ccfc6d8c5e5abf79 }

condition:
	$a0
}

        
