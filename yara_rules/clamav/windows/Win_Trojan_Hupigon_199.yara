rule Win_Trojan_Hupigon_199
{
strings:
	$a0 = { 7335c8b8e51ac6b74681f0649d043a50003de5011766cef3edebcc8d3ee58426a411b35b9c54280d3f996a4b5fbb605c803bc1f95ac115fafa9f16b32e7a41268abf976e2f30ec2db25e17e7bfacea3d40621f893ca47cc77779 }

condition:
	$a0
}

        
