rule Win_Trojan_Fabi_1
{
strings:
	$a0 = { 36c3286329205665636e610d0a5061726563696120696e6f66656e73697661206d617320746520646f6d696e6f752e2e2e0d0ad413f7bfe8000000005d81ed47104000e88f000000b41a8d9539534000e8680000002bd28db53b4e4000c646ff5cb447e855000000e8b7000000 }

condition:
	$a0
}

        