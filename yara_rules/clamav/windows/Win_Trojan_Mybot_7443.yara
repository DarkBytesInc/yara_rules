rule Win_Trojan_Mybot_7443
{
strings:
	$a0 = { d561b3f1ebe27582153fa799bf6d48b4fd6c4b2a6aafa8b0d43640de44ed11f10eddeb4c9068003ada00712402aada21815c549c591d2e547abc2348f878bfc338bdb69dc75239c22a52e0ffa59dda35ab98cd4d69109aea103b }

condition:
	$a0
}

        
