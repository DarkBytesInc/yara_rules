rule Win_Spyware_1282_2
{
strings:
	$a0 = { 09000000633a5c73662e657865000000633a5c3032302e7478740000ffffffff16000000bfb4b5c4bcfbb5c4c3feb5bdb5c4b4f3cbf8d2bbccf50000ffffffff21000000b4a9d4bdc9eebfccbaf3bcd2b5c4bdf1ccecb9a4c8cb68666b6a73 }

condition:
	$a0
}

        
