rule Win_Downloader_Small_1269
{
strings:
	$a0 = { 6874e270383a2f807579782e6b3462716f776dea697f7a39706e3c329c6578ab1f0f73691f8d2e633aebfe440a6c6261721c5efa72ea7852791af23497169035ede7fb61d7df4770682e0375726cf96f6e2e202a55524c7b447c77f52e0f935412f30104633a5c77b8b7de30606b6d67ac948d34c43269cb0ad072617934fe4633c776687d6e1f34c834d3ffc661d68f33 }

condition:
	$a0
}

        