rule Win_Trojan_Moonchild_1
{
strings:
	$a0 = { 2e8b584050c317e8efffffffeae82a000000ffe803000000eb09ffd9d0cb58404050c3e8f6ffffffea04e80d000000eaeb01e9e8150000009651eb1ce8baffffffe9e8d7ffffffc787584050c35883c00280f155ffe0ff2426880c }

condition:
	$a0
}

        
