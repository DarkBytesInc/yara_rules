rule Win_Trojan_SdBot_3856
{
strings:
	$a0 = { b4ce76ee6f2da46ecb737655fdbfe0d9c5842d030ccb8e165d687664fb41319f08d7c54ff93b494e7e54b1e6db9b746f31ce01b76638a6694fd0142d7e133dfe5ffa05e8c27b0d046b04af495e0a4cc4134b2bc780 }

condition:
	$a0
}

        
