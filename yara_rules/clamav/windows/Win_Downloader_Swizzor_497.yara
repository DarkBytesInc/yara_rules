rule Win_Downloader_Swizzor_497
{
strings:
	$a0 = { 9077dee60bbb6da724cdace7623b24bb6e2904f34ea5aba1051ad3cb11a1d09be5e14c76b3e5c93771d0f7c24bc1412c649e93ff977d6bce5c0fb59256e488f27ee229c50b8b51aa047d790d5e7d38acb78a7e30096b74d9c0731656524cc116b919016a97cf3d7ccc }

condition:
	$a0
}

        
