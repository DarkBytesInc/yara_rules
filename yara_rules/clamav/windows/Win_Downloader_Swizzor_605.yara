rule Win_Downloader_Swizzor_605
{
strings:
	$a0 = { 514e9d4db55a57ba4a66e701ddec7ec56371eb9b2c204d0d5a0bed6336ea7e4c66fdb5a32810adc57af683728e337b1788354f829e7e1e59b4fa7a864ff5ea8b7275c0ae66cb5e0d9ac22db65faae4bb364e099bad7a3b58d2db5ead1b449e9b2419a9b5cb95475133 }

condition:
	$a0
}

        
