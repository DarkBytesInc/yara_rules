rule Win_Spyware_Banker_1229
{
strings:
	$a0 = { 60a56797304d5f9ba25e4c79602e696c793a92d4970aa0915e680bb7692db1fcdb563ba4bbe5bcd24cd5d902efd4e9d3ed2ae16e9ad5e5260624ceb4f0175f67c2fae465a32c7397e8e7f8a5ffd4e2605afe1d8dd4a7cba92f3e }

condition:
	$a0
}

        
