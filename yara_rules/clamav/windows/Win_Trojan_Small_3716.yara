rule Win_Trojan_Small_3716
{
strings:
	$a0 = { 13b4e06cbecbdb2dd7215741ff1baed3bf1ec051d20b58bea63d5b69be4e1c82bd407c81bde16079fecbb7c71b27b12c1523c069cecb58d3c6ca6da1ce0b58b9bde19479fecbe35929ccc28c14365868d41f68a9be5018def0569599ce0b58bfbda3dd2933f1ae68964cd499bd28cd7114cb2f }

condition:
	$a0
}

        
