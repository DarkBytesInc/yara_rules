rule Win_Trojan_Spambot_79
{
strings:
	$a0 = { 6f28dc4d90868c03bae9eb652d37d6a22dabae8ad71ea0fff8d55f2f5e9d2fc1e63702141c1e2736648cd8ffe1ffff70bd66ec194dd53b091a9ec28755dc9d80ac443ffb9105a2cb75fffffff4b8d73af4497466ae0c06e44d28478810100c8f8c1ba1f83af9ddfffffffff0bd7b }

condition:
	$a0
}

        
