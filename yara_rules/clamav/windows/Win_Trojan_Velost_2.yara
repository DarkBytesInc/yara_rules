rule Win_Trojan_Velost_2
{
strings:
	$a0 = { 60e80a00000064678b260000ff642428[0-150]c9b10ffcf3a675da8bf28b5d2403de0fb70c438b5d1c03de8b1c8b03de83ec688bfce80b0000004d657373616765426f7800e80e }

condition:
	$a0
}

        
