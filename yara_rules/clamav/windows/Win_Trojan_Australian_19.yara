rule Win_Trojan_Australian_19
{
strings:
	$a0 = { b922040eba7e2e1fbb980043315f7e31577e314f7ee2f478efefd1dc3aa3e550efee6a515ce6134a4b575bc73ad6d62c9bb96b27e1f8a7612f544710b1126841b04e497e6360cb6a68e6b0438ffdde6869d169646e7f9bcc457850 }

condition:
	$a0
}

        
