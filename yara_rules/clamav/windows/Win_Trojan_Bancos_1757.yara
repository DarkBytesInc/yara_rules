rule Win_Trojan_Bancos_1757
{
strings:
	$a0 = { a4bc0d362303a67ac5d0628c7b400024ae45a4392d2c426f39f9fd2a3c702ec70f67ceda1c97400835bc23c8c78578b1d9f56f98a1785c6f22c0e4c7988af855e4fc4d0ee185 }

condition:
	$a0
}

        
