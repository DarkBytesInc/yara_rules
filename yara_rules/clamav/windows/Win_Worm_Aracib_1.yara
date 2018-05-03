rule Win_Worm_Aracib_1
{
strings:
	$a0 = { 558bec81c480f6ffff535657c745f8f4010000beb4e140008dbd50feffffb96a000000f3a568f40100008d8574f8ffff506a00e89bc00000 }

condition:
	$a0
}

        
