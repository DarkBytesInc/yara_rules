rule Win_Trojan_SdBot_3691
{
strings:
	$a0 = { 4e78af74398a6a9da5d8fa49955331d16db298169024136da696d7cb0ee6e35cde319fc72ed6dc4df44038a66faf93790f4edcd7218051dc2bb919a8341de1f7f7ed423f96e782009bd2c40527b8 }

condition:
	$a0
}

        
