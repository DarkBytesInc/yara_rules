rule Win_Trojan_Lineage_298
{
strings:
	$a0 = { 9bc57f26e5b32246ad377d6d325f9b80b9fd77a1c596595b6b78cf40e830ce170070acde18e17723d01232c7c1dc0863be43366cbc90da498c21ffa5c3cc9e1ccb421e2b76f626bb24dcefc74cfe1dcf3eb900173b204ff8eaeda677 }

condition:
	$a0
}

        
