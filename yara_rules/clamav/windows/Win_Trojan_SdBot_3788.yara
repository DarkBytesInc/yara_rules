rule Win_Trojan_SdBot_3788
{
strings:
	$a0 = { 40f36b6b21c84a6c10abd5bcd4d74901f9c1cf8a1c939ad641b40b5f3a36001aedcfdcb4fda4b5ef67939917dcb3ea0d7bbfbb9bf35e1834d80381466b60bd5055314bd4ad907bee9b1db78ad1624a3c412d4d9c9f014446874de2f76f7d0391a423 }

condition:
	$a0
}

        
