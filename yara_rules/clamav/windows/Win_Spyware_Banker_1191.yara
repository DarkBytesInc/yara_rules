rule Win_Spyware_Banker_1191
{
strings:
	$a0 = { 45a28ac3bd58d10ed67ca45e6c7cd0902e1c56d964dd0427d910e1de79c0fc8c145d9c72a6ca39421e62a61bb76ce7d6f16ffcebce4b4f0f39da16a46d74fa6d2fda0a19fccfbb13bf97b4b24abe2ed8f99103ac4b46cacb2557 }

condition:
	$a0
}

        
