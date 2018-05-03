rule Win_Ircbot_Apulia_4
{
strings:
	$a0 = { a7aaf1abe4b4eab7ecace850a7fdfb62e82108fedbd79ce290f68d58b19dca8bfef8e2b6a1ff98f190ea97b0b4dcaa21fbc0b5cfa4feaef82aa2cdb21ffec0a0dabad0ab58cbaddaacd6bc1efed7fef013b6e39ff4e0a5bdd7b5a587ddd296f79df0f58dfef18a }

condition:
	$a0
}

        
