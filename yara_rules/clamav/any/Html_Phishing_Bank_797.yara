rule Html_Phishing_Bank_797
{
strings:
	$a0 = { 746f206f6666657220796f7520746865206265737420706f737369626c6520696e7465726e65742073656375726974792c207765207265717569726520796f75206765742074686973[1-7]6672656520736563757265207570677261646520746f2068656c702061766f696420667261756420776865726576657220796f75206163636573 }

condition:
	$a0
}

        