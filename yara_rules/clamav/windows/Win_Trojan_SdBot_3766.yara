rule Win_Trojan_SdBot_3766
{
strings:
	$a0 = { c84191d8b6bc9a174dc93d4bcc89496dd6079d184fea33cc35d18857c2c8b6bc9a3fb97fcaccead40a33ead429cb9c6bd46bccde03f5a203e2b0dedc573acc6aa27a6f55f81581aeb8f5a084e259b9d09198358da89b299b94a1d0f8d4ddd02890d89e2323cb4b4a23bdd4f866b8 }

condition:
	$a0
}

        
