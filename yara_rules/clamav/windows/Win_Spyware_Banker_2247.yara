rule Win_Spyware_Banker_2247
{
strings:
	$a0 = { 70c86525007fe4e7fc7fe582acf80a60a0391f4e3194ae067c2e2458fa0a609ec243abf9c597c08780e9aed20c7a4b004bc85312348de9cadeab08e00a7dd60d4e42df8e304fd192ea5de4a61fe9b216a4a23a6760fc7fa1873aba0f39c053f63a5379c33017bd39dc01bc0525e33de0e412e4e4ff1140ee2eba0a84584cc563c9c716ae157db9b8c19e822ffb88b157684b056cc885 }

condition:
	$a0
}

        