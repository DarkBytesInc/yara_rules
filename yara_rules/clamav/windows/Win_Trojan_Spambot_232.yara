rule Win_Trojan_Spambot_232
{
strings:
	$a0 = { 99f0ffffff870631050508aa007ffb222e4c426e8cbe99b87e6c95cdb115ffffc71259330f067e0382276d52cb71fa09d082a18dffffffffb44aadf25e888bc4535f28603fd10ee8bfce6753bfeafa901365574762a90322ffffffff4a4ca25a4173a0e35dbe52277c51fbd87691 }

condition:
	$a0
}

        
