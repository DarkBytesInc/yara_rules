rule Win_Trojan_Hupigon_301
{
strings:
	$a0 = { 2d90dde73bf55181ce7143dea05af1e86999fc47ec2916aa4a6e8b4dd89cf45a305b789855a4d487c86afb2cf2a03ef314225dee0ed3a9953a570ef8f130165ecaa2fdc1a194ee7a916ba05de841fbb5f3506e80bb1dd2cf86a1 }

condition:
	$a0
}

        
