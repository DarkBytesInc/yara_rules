rule Win_Trojan_Uvc_3
{
strings:
	$a0 = { 0300b88d42cd2150f7d85048502d2dfb5858587403e822008cd80510002e01863a002e01863c002e8e963c002e }

condition:
	$a0
}

        
