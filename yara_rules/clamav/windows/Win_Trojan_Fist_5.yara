rule Win_Trojan_Fist_5
{
strings:
	$a0 = { 5db8ffffcd210bc0750ae83d02be000156c2ffff1e33c08ed8ff0e1304c51e84002e895ef92e8c5efb8cc34b8edb812e03008000a112002d8000a312008ec00e1f8bf583ee07bf0001b9ab02fcf3a48ed9fac70684006e01a38600fb }

condition:
	$a0
}

        
