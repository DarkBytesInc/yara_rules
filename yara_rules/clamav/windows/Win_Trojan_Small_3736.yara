rule Win_Trojan_Small_3736
{
strings:
	$a0 = { 244ac902a05df1fcf7efb1ff096ec4eca1da981ea485b02f659eaf21c59dafc2a995f0ac00e40d08fa4807040986c0aca1efb8abb6bdc0eca1d5afc2dd95f0ac2c761bad0ba90617a184c600b1c5b03161fae237deb5c0eca1dbaf84264625d2f784882d1db6af09168e06ac780615dda08618 }

condition:
	$a0
}

        
