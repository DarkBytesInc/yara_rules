rule Win_Trojan_Bancos_1226
{
strings:
	$a0 = { 67e8995b59d3ac257d5ed88d7ff538b7c6e9a506ecb0cd7666fbed038d0c36dca8b763320dbc62cea668466193faf6ee4968514d8f5a664fdce8574cc7c704ef8de3f08026dc9bc4f5f5e90c2d8be10191ad29248dfcfdbad5d96cb356bffd }

condition:
	$a0
}

        
