rule Win_Spyware_Banker_259
{
strings:
	$a0 = { 470f29a63b8a1da603a8f47c1a70218525270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a9580b3ca53e6c229cbff3ec763fce1f2a9dca3cf8ff69aead71c3367cb04eada16b12a3fac7df8c77ae5352ac4a96fdbdf3b4b449c96a59484b2b55dfd2d6cb95bfb2aaae9c60305b9c89ba9e05d82977 }

condition:
	$a0
}

        
