rule Win_Trojan_SdBot_4499
{
strings:
	$a0 = { 6c1a8ec127e857a5eb346e738e24af85dd022bba51889245d8d88340b22547c4ce4a165b9fd1ee1608a16a1ad06fff7ee4fdba246602bc34d7dce2c53bb4a0a452a98a4539ad725e6411bed9f5d16eb14f61205e6d9911fd36fcd9891eb10c1a5fa98ece637644c6464e97fae13a8e979088893f61b21419cd26c685ed10ecd1bc0d80de1ea7ecb2a1aec7ce392281f7030bd9d1d144 }

condition:
	$a0
}

        