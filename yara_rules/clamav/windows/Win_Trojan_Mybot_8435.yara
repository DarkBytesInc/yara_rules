rule Win_Trojan_Mybot_8435
{
strings:
	$a0 = { 906f6799872007496ee65ef05067c8d6a54be05edb4eadd0a542c52dea392b80ee0f4d587ede738fb09f435a552cee76036cfe5e2ada59b0d64096e8bf815c893e2b5fa62391cf124a98786cd533f00f71014bceec }

condition:
	$a0
}

        
