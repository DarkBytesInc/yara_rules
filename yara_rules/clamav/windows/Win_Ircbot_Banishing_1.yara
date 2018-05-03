rule Win_Ircbot_Banishing_1
{
strings:
	$a0 = { 777a6c7a487a5a8ab749b749e2c25b193c0fb31c5f49b7149972f1b8ea3fa557e1c76fc2c14b1b75 }

condition:
	$a0
}

        
