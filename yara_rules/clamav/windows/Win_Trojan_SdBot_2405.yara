rule Win_Trojan_SdBot_2405
{
strings:
	$a0 = { 9a529562b034a5420b6ec862c636847300b716c2d2baa68728dbdc7eb8a1c2c0c9a6736c43c5c9a5a5ac2d88ca6d5a05b53aa62706b54a6d8bd4e6ff7d9ef79cb445d8fcedbfdfedff5f3f9f9e9cf3bcb7e7bd3feff33e974387f0171ab6df60088dda8047c3313c86dbf068fe151e23 }

condition:
	$a0
}

        
