rule Win_Trojan_Mybot_7174
{
strings:
	$a0 = { b1df821c615a8c7a6a91316ba4d8db482bd36f7eacbdbea62ad776af269ae7f91ce75f88a17e43c0b4aba3d64e231136c9f08c26fee93422f278928d8b57b1ce38fc29cdbde67585d8e5bac52338aa1f4b307a04407e65f76093ca996c84e5e14a42abbfbf59fe6099c70bea629775b90db7da }

condition:
	$a0
}

        
