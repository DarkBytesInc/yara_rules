rule Win_Trojan_Small_3697
{
strings:
	$a0 = { 139d35b4bcdbcd4b91af0de4fd8355e7a89b50a8c1f1ccbbe9eb234eaaee35ccbcdbcd38910dd0e3a81e91fca710f1fba7b1d5f3e89b2c4206f726a7fff235e4b89bcd4db19ae21bb9dbcd33a8b109f4e89b58d4139c3707ff05cde2beefdd23a9208d58db260a14b9dbcd39a87352a41dc123 }

condition:
	$a0
}

        
