rule Win_Trojan_Small_3666
{
strings:
	$a0 = { 60e60671e370a79a5ca8a119d14de0e0ebf6ade0ebf6ade0ebf6a89c7f6aa7a47f6ea751df26915c95289158e5a71e91df269244aff036831ba1f75ff02665ab7e27e0e0ebf6ade0ebf6a8947f6aa818e6765dd42d }

condition:
	$a0
}

        
