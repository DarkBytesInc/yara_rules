rule Win_Spyware_Banker_3427
{
strings:
	$a0 = { 7e1b481b280b40d75b1c330f7d28d7d152270db1e88a17a4836b4cd0a02630fac61c5c3b3eee8f8e84ceb176a2c5c04462d4c181fea5b00314cec0be43d63208ad463c313274d2c5d5aaddf185fd46b32b3fa417b5a772a8231a4b9b1ca33a }

condition:
	$a0
}

        
