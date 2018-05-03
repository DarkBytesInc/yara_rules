rule Win_Ircbot_generic_5
{
strings:
	$a0 = { 20546f74616c204b6f6e66757a696f6e0d0a3b0d0a6e303d6f6e20313a4a4f494e3a233a7b0d0a6e313d202f69662028 }

condition:
	$a0
}

        
