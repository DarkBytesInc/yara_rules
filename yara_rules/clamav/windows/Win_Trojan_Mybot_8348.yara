rule Win_Trojan_Mybot_8348
{
strings:
	$a0 = { fec6c449b98e5eab6f061992444cf49d3617bf3786f657616b55b57d33dd6c90a4dd79c20d65ec1cffef7540208f778f99845713d42cf3f6ddef836a536598808b30ddd2820b33006bfe34804d2ffa1dd1b6ded43d }

condition:
	$a0
}

        
