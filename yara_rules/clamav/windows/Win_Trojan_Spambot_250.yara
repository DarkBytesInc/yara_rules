rule Win_Trojan_Spambot_250
{
strings:
	$a0 = { ffe8a19a2bf797bc8626f6f3361f8573c39e2e5e3efb1bd5f051bf750b744ffe58ffffffffa8cc016b90cd2606cd1a71fc58b10f3a0915de8f25c7f9258faa9335d0647f01ffffffff9f3d9d169b6ae1984f24c3b447fcf76791538d912a1c66e7ca0bfcef09d5cf1ffffffffffb }

condition:
	$a0
}

        
