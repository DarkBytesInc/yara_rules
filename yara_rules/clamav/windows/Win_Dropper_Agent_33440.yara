rule Win_Dropper_Agent_33440
{
strings:
	$a0 = { fad5cfeadbdffa18470cec78c9c6b19db7fd555de95fc5325c06b12a4ec1efc7ce3ccca271b0c42655923a081db161150e142f9eb31f25ec890d7caa656e82bbf270b66cfffdafa8b80000000000006b219b72ed807d9fb4ff5da1bce785a54f7b4557da1ec1 }

condition:
	$a0
}

        
