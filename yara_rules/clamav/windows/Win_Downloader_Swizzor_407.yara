rule Win_Downloader_Swizzor_407
{
strings:
	$a0 = { ae394973ec2f6cd320c5ebf6288f8201d47b09b24b5fe073a7ed1b063bff1789c7a5bcc21045786bb529d1813bcc79a51c9171c5bdc70301ae7ff6648e67ae32748f0e22048fa1ef15ddb925e61359c9270765dcffee5e36e5fd }

condition:
	$a0
}

        
