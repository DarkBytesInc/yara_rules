rule Win_Trojan_SdBot_2414
{
strings:
	$a0 = { 776515d6c80a26c0127cac46446505312aea19274a8008e139b7aabacf99338fe8eef7ddfffdfef7de3f3a39e7f4a3bababbbabbbaaaba3a5bfac1dd9a586c08f4deec982028cb0441905a931bf27679b75c0bef42368b8fe1f119d1e3659bc91ee87d005248ad10f5778cf1be171ebf }

condition:
	$a0
}

        
