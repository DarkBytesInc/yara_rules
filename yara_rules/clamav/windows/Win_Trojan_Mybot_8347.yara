rule Win_Trojan_Mybot_8347
{
strings:
	$a0 = { e744b080b02d63915c5ebce54ed4bcac405581868b4d1e2e26c5f72e9ee22ee1ba4804c37d72339a9ab3ad29102a87b3994e3f6bcde6faa54b4e56c20107ef39db5e8bd27adcfc9625e3778dcd35b1007458c08642 }

condition:
	$a0
}

        
