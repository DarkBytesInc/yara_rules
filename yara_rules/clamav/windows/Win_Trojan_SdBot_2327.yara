rule Win_Trojan_SdBot_2327
{
strings:
	$a0 = { 9665f7288e8374c82e1391aed2da36065f1a9e51ff1c14d3468cf9cfebee4b737e3de14d5deccb00720f67ffc70d42cd0d36d7ec3c79b998a3245615bb29c25378d08c53b66b2f840670be8655b64194ecbf383d5d }

condition:
	$a0
}

        
