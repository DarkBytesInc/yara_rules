rule Win_Trojan_Small_3728
{
strings:
	$a0 = { 8fa8f0cf63e8883c38308ce74f2b4d00a6a76028a0fef2e8a21071fb8fa8ddcfc1ab88e7d26ca1e6c4cca0e665b098275007e744ab014c3ea71089f74fa8f2ef4ebdc0f78fa8d8e665e49827503379525012ac3dbaa887fda3b8c8e7d468fd19dbe5b8f78fa8dee6272d495c75fe87bfd024b9 }

condition:
	$a0
}

        
