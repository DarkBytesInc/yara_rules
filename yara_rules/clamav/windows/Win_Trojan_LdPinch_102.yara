rule Win_Trojan_LdPinch_102
{
strings:
	$a0 = { 5952d85145d2e7adad286da22827adadadc5a0beb9bec5ee07bbbe456de4adad6ba8db07bbbef16ae855a9acadad20e855fdc5e506bbbec5ecbeb9bec5ee07bbbec5afadad2d45d85a5252a66dd9e9c5e506bbbec7adc7ad45ce5b52526ae855 }

condition:
	$a0
}

        
