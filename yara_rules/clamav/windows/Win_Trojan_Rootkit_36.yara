rule Win_Trojan_Rootkit_36
{
strings:
	$a0 = { 8b65e8834dfcff682a0701008d45dc50ff15940d01008d45dc50ff15900d0100837de4007409ff75e4ff158c0d0100e82b050000c20400 }

condition:
	$a0
}

        
