rule Win_Downloader_371_1
{
strings:
	$a0 = { 80eea9837da00c7d05e9290200008b45a0898574ffffff80c9f883ad74ffffff0cc6852fffffff4f80c19e80e516c68532ffffff2eb12780c9c0c68530ffffff5280f18280cdc6c68534ffffff58c68535ffffff45c6852cffffff58c68536ffffff00b1cbc6852bffffff45 }

condition:
	$a0
}

        
