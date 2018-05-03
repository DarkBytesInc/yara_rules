rule Doc_Trojan_WordDigger_1
{
strings:
	$a0 = { 49662064632869292e4e616d65203d2022576f726444696767657222205468656e }

condition:
	$a0
}

        
