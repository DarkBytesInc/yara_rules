rule Win_Trojan_RAdmin_18
{
strings:
	$a0 = { 2b8b089cf78e9847450efa6f9326a8326adad4d4222598073ac8119b4fdde70ea8e9faff0acaf41f4848d506c784cd0bed0e1a20a5ba05d60b0abf7b802ef232af15e0f262d12aade278aab3935eb78fd5db0c20bbe6f6c953d2d8af1b2579e92f237e629fcf8f5501d9914ab32d8ac0f6688d61d8b8a5d3c9f49a }

condition:
	$a0
}

        
