rule Win_Downloader_Delf_2065
{
strings:
	$a0 = { af0f092eadabad556228b488fd17a31010efbefd3491f98ac4c6329160f117004c5eafc681dbbca8b7b3b8b4adaab168680084a4afa6a0b6bfe2e2a7aef46ffd11e8a0bc819c9d5e8fc0c3889e9fd84004808082c6cbc5c9c3cfd7c1d7c391aeb0f5ecfcec11da0600f0e8b9f5faf9bdf0e3bfece7e9efe7e7f15d0c1e36abee }

condition:
	$a0
}

        
