rule Win_Trojan_Mybot_6853
{
strings:
	$a0 = { a5be5031f607ea6cae1b977a68939bf9731d903ff527978faa63f98202922e97121dec9b742878e2877a957ccbc7e8046e32dd6dbb0398e05685798f40873c85b393abb70a91d9def3fdce1199315a87cf7d25309c8c8383a1a2b68ae01673a0aa04980fb09cf518b85fb443a306d12b1b0ec27038b3b59b4b76db96f1e3a1cf41d45a391d302b2ffbc347e95495423ac3db69fd364a }

condition:
	$a0
}

        