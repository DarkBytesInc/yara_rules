rule Win_Trojan_Bancos_1098
{
strings:
	$a0 = { bcfd6db7715d01ce0a7f1d49feabee706197c8a089cd31fb6f9b1ea80dc41adec628d8751d415e730c364fc218c581bffe96789cad9856df9624a74c6f6798cf671fe40d778321f9770ff51ef3724045f718527be1c5ee2a5dc2aad9cc8a910cac7dbf02db01 }

condition:
	$a0
}

        
