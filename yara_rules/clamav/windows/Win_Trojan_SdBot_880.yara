rule Win_Trojan_SdBot_880
{
strings:
	$a0 = { 5cb2730bfcb8e166781e0160ff0375f96c88c291b61d73d80ef178e7a7b5c9f36edabbf63790b306e71ba77e60de760667ffe49f94aea23e5c3c039b29d481cf011a76d620b9af5c5ef886822bedec7362953ee220aefde94dde2cbe1a01a9617cd7abc6ceb97ac3aaee2850c0e90df3 }

condition:
	$a0
}

        
