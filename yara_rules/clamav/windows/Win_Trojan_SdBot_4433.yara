rule Win_Trojan_SdBot_4433
{
strings:
	$a0 = { 9b13dcb5d20242482e48caddab04e40c46def1c11931ffc2301a1c176a86322d836065f9c6250ff898b0c5cb201fba22275b3aa04b31f8a56dd11d1b0dee93d9b248ab5f717f0bd80696e8126fd97e8a3472 }

condition:
	$a0
}

        
