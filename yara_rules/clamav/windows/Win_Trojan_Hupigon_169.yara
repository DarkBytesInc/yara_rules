rule Win_Trojan_Hupigon_169
{
strings:
	$a0 = { 8c84102e1385a76005f25b6a0ffde6f5d37b53b8dac4aaee42c8ab5e7da1e6f8318141d505c5ccccb08227f063c8a1a14bcd5a3ec9f36aec552ba5fc51cf3881b051c286898fcf4c16b28a8be7b72c51dc0a6432eee5c0e8e36797f7edc1b5844b4d8a9ee67697a15c }

condition:
	$a0
}

        
