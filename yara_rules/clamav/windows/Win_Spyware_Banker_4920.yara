rule Win_Spyware_Banker_4920
{
strings:
	$a0 = { 5a929381726284a3a91c8435e4473ed096775383b4671edcb56b35b365c82fa99c3ad0533a94080bd83970b5ee1849b8f9abc8988b5d527be337db5968417516c66b8ea066bce4f61d9361a7efb3c82741cd121c7f7c5548bbb9c71d03b66250f1969a04e158d98ebda024b7987fc1ef709352c9d1585bacf7101645414b88eb16b500c585eb9a576366c273b7338fe378e96ff0dfe7 }

condition:
	$a0
}

        