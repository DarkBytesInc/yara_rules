rule Win_Trojan_TestSpy_1
{
strings:
	$a0 = { 7472616e6765727320546573740000cef8e8e1eae020e8ede8f6e8e0ebe8e7e0f6e8e820eff0eee3f0e0ececfb0000737472000000000042494e000a4572726f723a20 }

condition:
	$a0
}

        
