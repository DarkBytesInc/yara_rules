rule Html_Phishing_Pay_8
{
strings:
	$a0 = { 69742068617320636f6d6520746f206f757220617474656e74696f6e20746861742064756520736f6d6520696e7465726e65742066726175647320736f6d65206163636f756e74732068617665206265656e2073746f6c656e2e207765206e6f77206d7573742074616b6520736f6d6520616374696f6e7320616e642076657269667920616c6c }

condition:
	$a0
}

        