rule Win_Trojan_Spambot_245
{
strings:
	$a0 = { aba737f1fc1128fb9098ffffffff71a860c93969e6ab8d01484f8aab263fe9e7be2edc49b34a58370f6b139f8437ffffffff84cf2acfd69e15e5df273924a4adbd0986a29d50b9f8a3cef4794e4024294e0dffffe2ff3d161efde668a3c400cccedb99e7b28fb6d87da8f5a15973 }

condition:
	$a0
}

        
