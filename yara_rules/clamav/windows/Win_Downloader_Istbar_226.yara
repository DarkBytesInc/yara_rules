rule Win_Downloader_Istbar_226
{
strings:
	$a0 = { 898800002f6169643a2569202f6366673a2573202f736f66743a2569202f766b65793a2573202f746b65793a2573202f746c6f636b3a2573202f6578653a25730000000025735c6e5f25732e6578650025733f6169643d2569266366673d257326766b65793d2573000000008381848d8986898e828e828e858d8a86 }

condition:
	$a0
}

        