rule Win_Trojan_OW_1
{
strings:
	$a0 = { ff0019f5000000002704ff0b0500080046d4fefcf64cff3504ff00493aa4fe0600044cfffb9494fefdfe90fe04f4fe3ae4fe0700fb9404ff046cfffb94d4fe3ac4fe0800fb94b4fefdfe14ff0a0900080032040014ff90fe36080004ffd4feb4fe94fe0010042cff28e4fec800 }

condition:
	$a0
}

        
