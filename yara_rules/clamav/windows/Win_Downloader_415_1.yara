rule Win_Downloader_415_1
{
strings:
	$a0 = { 87771cf51e001b6b27aeec7adf235082a4e319f51e171cf61eaf6bf4d4e31af51eae91fd1dc433725fafa0b593c4a87a53ad1bf56fae91011ec457065fafa63a2b78df28df78df4aaa9b9de147b01bf5740686f588b11a0b472c5cf5a9a79ff41ebe9f771faf1b82a4871af51e76a1cd1dae1b1e20af }

condition:
	$a0
}

        
