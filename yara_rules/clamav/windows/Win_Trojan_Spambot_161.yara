rule Win_Trojan_Spambot_161
{
strings:
	$a0 = { a1b9e8ffffffff2d749995b4f274c866cd7bef3790e0036f6ecb4ae5366c62753c57484d6430c7ffffffff7772dff323a01fea9c53773f605e27c8af77810f32699bc44fe33354efcea781c1c34fdf846a0340ea5b69e96e85599bffffffff97c87b2b86bb62e7d9d3888393a00c }

condition:
	$a0
}

        
