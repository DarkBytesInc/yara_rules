rule Win_Downloader_Swizzor_393
{
strings:
	$a0 = { fdb3760a4088d785ad37bdf6a3a8bb6bab9bc46fcec56a027e14b5d361730d42816bd497d181ac7a3c4dfa602edfa1c54b2b5f3824603c2afae42f989bfd76efed72c718b5dd6e454f908a5a8af97a00aa7bb22f100710c396c8 }

condition:
	$a0
}

        
