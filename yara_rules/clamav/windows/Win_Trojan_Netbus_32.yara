rule Win_Trojan_Netbus_32
{
strings:
	$a0 = { 13c46ec8e45842fce580d251de9ed84e79bd422eb0247dadbc9abc4a4d59423f8410056150a64ef4c5746403df55158bf3fde72c4e9f7d49d0404f8068a9d86dfdf1b465bae6d2feec3b228f8da083df9235f3e6744a8bf767af9da763e4ee60f8a88c58 }

condition:
	$a0
}

        
